#!/usr/bin/python3
import os
import sys
import argparse
import string
import random
import boto3
import subprocess
import yaml

def create_workshop_ou( name, scp_template, account_ids, cfn_template):
    organizations_client = boto3.client('organizations')
    list_roots_response = organizations_client.list_roots()
    root_id = list_roots_response['Roots'][0]['Id'] 
    create_organizationl_unit_response = organizations_client.create_organizational_unit( ParentId=root_id, Name=name )
    ou_id = create_organizationl_unit_response['OrganizationalUnit']['Id']
    scp = open(scp_template).read()
    create_policy_response = organizations_client.create_policy( 
        Name=f'{name}-service-control-policy', 
        Description=f'{name} service control policy',
        Content=scp,
        Type='SERVICE_CONTROL_POLICY')
    policy_id = create_policy_response['Policy']['PolicySummary']['Id']
    organizations_client.attach_policy( 
        PolicyId=policy_id,
        TargetId=ou_id)
    
    for a_id in account_ids:
        move_account(a_id,ou_id) 
        account_details = setup_account(a_id, f'aws-{a_id}',cfn_template)
        print(account_details)

def remove_workshop_ou( name ):
    organizations_client = boto3.client('organizations')
    root_id = organizations_client.list_roots()['Roots'][0]['Id'] 

    ous = organizations_client.list_organizational_units_for_parent(ParentId=root_id)['OrganizationalUnits'] 
    ou_list = [ x['Id'] for x in ous if x['Name'] == name ]
    if len(ou_list) > 0: 
        ou_id = ou_list[0]
    else:
        return 

    accounts = organizations_client.list_children(ParentId=ou_id,ChildType='ACCOUNT')['Children'] 
    account_ids = [ x['Id'] for x in accounts]
    if len(account_ids) > 0:
        nuke_accounts(account_ids)
        for a_id in account_ids:
            move_account(a_id,root_id) 

    policies = organizations_client.list_policies_for_target(TargetId=ou_id,Filter='SERVICE_CONTROL_POLICY')['Policies']
    policy_list = [ x for x in policies if x['Name'] == f'{name}-service-control-policy']
    if len(policy_list) > 0:
        policy_id = policy_list[0]['Id']
        organizations_client.detach_policy(PolicyId=policy_id,TargetId=ou_id)
        organizations_client.delete_policy(PolicyId=policy_id)
    organizations_client.delete_organizational_unit(OrganizationalUnitId=ou_id)

def move_account( account_id, target_ou_id ):
    organizations_client = boto3.client('organizations')
    list_parents_response = organizations_client.list_parents(ChildId=account_id)
    parent_id = list_parents_response['Parents'][0]['Id']
    try:
        print(f'moving account {account_id} to {target_ou_id}...')
        organizations_client.move_account( AccountId=account_id, SourceParentId=parent_id, DestinationParentId=target_ou_id)
        print(f'account {account_id} move to {target_ou_id} complete.')
    except organizations_client.exceptions.DuplicateAccountException:
            print(f'account {account_id} already ou {target_ou_id}.')
    
def setup_account( account_id, account_alias, cfn_baseline_template ):
    organizations_client = boto3.client('organizations')
    describe_account_response = organizations_client.describe_account(AccountId=account_id)
    account_name = describe_account_response['Account']['Name']

    sts_client = boto3.client('sts')
    assume_role_response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole',
        RoleSessionName='boto3_setup',
        DurationSeconds=900 )
    session = boto3.Session(
        aws_access_key_id = assume_role_response['Credentials']['AccessKeyId'],
        aws_secret_access_key = assume_role_response['Credentials']['SecretAccessKey'],
        aws_session_token = assume_role_response['Credentials']['SessionToken'])

    #DO: Setup Account Alias
    iam_client = session.client('iam')
    account_aliases = iam_client.list_account_aliases()['AccountAliases']
    for aa in account_aliases:
        iam_client.delete_account_alias(AccountAlias=aa)
    iam_client.create_account_alias(AccountAlias=account_alias)

    #DO: Setup Account Admin
    iam_user_name = 'administrator'
    iam_user_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation,k=12))
    iam_client.create_user(
        UserName=iam_user_name)
    iam_client.attach_user_policy(
        UserName=iam_user_name,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    iam_client.create_login_profile(
        UserName=iam_user_name,
        Password=iam_user_password,
        PasswordResetRequired=False)
    access_key = iam_client.create_access_key(UserName=iam_user_name)['AccessKey']
    access_key_id = access_key['AccessKeyId']
    secret_access_key = access_key['SecretAccessKey']

    cfn_client = session.client('cloudformation')
    cfn_template = open(cfn_baseline_template).read()
    cfn_stackname = 'org-member-baseline-stack'
    stack_result = cfn_client.create_stack(
        StackName=cfn_stackname,
        TemplateBody=cfn_template,
        Capabilities=['CAPABILITY_NAMED_IAM'],
        EnableTerminationProtection=False)
    cfn_waiter = cfn_client.get_waiter('stack_create_complete')
    cfn_waiter.wait(StackName=cfn_stackname)
    baseline_stack_output = cfn_client.describe_stacks(StackName=cfn_stackname)['Stacks'][0]['Outputs']
    return {
        'login_url': f'https://{ account_alias }.signin.aws.amazon.com/console',
        'account_name': account_name,
        'user_name': iam_user_name,
        'user_password': iam_user_password,
        'access_key_id': access_key_id,
        'secret_access_key': secret_access_key,
        'baseline_stack_output': baseline_stack_output
    }

def nuke_accounts(account_ids):
    sts_client = boto3.client('sts')
    this_account_id = sts_client.get_caller_identity()['Account'] 
    config = {
        'regions': [ 'global', 'us-east-1' ],
        'account-blacklist': [ this_account_id ],
        'accounts': {}
    }
    for a_id in account_ids:
        #WRITE AWS-NUKE CONFIG
        config['accounts'][a_id] = {
            'filters': {
                'IAMRole': ['OrganizationAccountAccessRole'],
                'IAMRolePolicy': ['OrganizationAccountAccessRole -> AdministratorAccess']
            }
        }
        with open(f'aws-nuke.{a_id}.config.yml', 'w') as out:
            yaml.dump(config, out, default_flow_style=False)

        #GET ACCOUNT PERMISSIONS FOR NUKE
        assume_role_response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{a_id}:role/OrganizationAccountAccessRole',
            RoleSessionName=f'boto3_{a_id}_nuke')
        aws_access_key_id = assume_role_response['Credentials']['AccessKeyId']
        aws_secret_access_key = assume_role_response['Credentials']['SecretAccessKey']
        aws_session_token = assume_role_response['Credentials']['SessionToken']

        #RUN AWS-NUKE FOR ACCOUNT
        command = f'aws-nuke --config aws-nuke.{a_id}.config.yml --access-key-id { aws_access_key_id } --secret-access-key { aws_secret_access_key } --session-token { aws_session_token } --force --no-dry-run' 
        process = subprocess.Popen( command, 
            stdout = subprocess.PIPE, 
            stderr = subprocess.PIPE, 
            universal_newlines = True, 
            shell = True )
        while process.poll() is None:
            stdout, stderr = process.communicate()
            print(stdout)
        return_code = process.poll()
        if return_code != 0:
            raise Exception(stderr)
        print(stdout)

##
# RUN
##

parser = argparse.ArgumentParser(description='aws workshop management application.')
parser.add_argument('--action', metavar='action', help='operation to perform for workshop management',required=True  )
parser.add_argument('--ou-name', metavar='ou_name', help='name of AWS Organizational Unit' )
parser.add_argument('--account-ids', nargs='+', metavar='account_ids', type=str, help='the list of AWS Account ID\'s')
parser.add_argument('--account-name', metavar='account_name', type=str, help='AWS Account Name for ACCOUNT_CREATE action')
parser.add_argument('--account-email', metavar='account_email', type=str, help='AWS Account Email for ACCOUNT_CREATE action')

args = parser.parse_args()
action = args.action
ou_name = args.ou_name
account_ids = args.account_ids 
account_email = args.account_email
account_name = args.account_name

cfn_template = 'aws_account.baseline.yml'
scp_template = 'aws_org.ou.scp.json'

if action == 'ORG_CREATE': 
    organizations_client = boto3.client('organizations')
    organizations_client.create_organization()

elif action == 'ACCOUNT_CREATE':
    if  account_email and account_name:
        organizations_client = boto3.client('organizations')
        organizations_client.create_account(
            Email=account_email,
            AccountName=account_name,
            RoleName='OrganizationAccountAccessRole',
            IamUserAccessToBilling='DENY')
    else:
        print('insufficient arguments')

elif action == 'OU_CREATE':
    if ou_name and account_ids and cfn_template and scp_template:
        create_workshop_ou(ou_name,scp_template,account_ids,cfn_template)
    else:
        print('insufficient arguments')

elif action == 'OU_REMOVE':
    if ou_name:
        remove_workshop_ou(ou_name)
    else:
        print('insufficient arguments')

elif action == 'ACCOUNTS_RESET':
    if account_ids and cfn_template:
        nuke_accounts(account_ids)
        for a_id in account_ids: 
            account_details = setup_account(a_id,f'aws-{a_id}',cfn_template)
            print(account_details)
    else:
        print('insufficient arguments')
else:
    print('Unknown Action')

#388788293040 679849565988 286977136502 197674896730 189296060252 552378307776 985781703276 472484061983 569328080461

















    