# aws-workshop-v2

python3 workshop.py --action ORG_CREATE

python3 workshop.py --action ACCOUNT_CREATE --account-name <account_name> --account-email <account_email>

python3 workshop.py --action ACCOUNTS_RESET --account-ids <account_id_1> <account_id_2> ... <account_id_n>

python3 workshop.py --action OU_CREATE --ou-name <organizational_unit_name> --account-ids <account_id_1> <account_id_2> ... <account_id_n>

python3 workshop.py --action OU_REMOVE --ou-name <organizational_unit_name>
 