FROM amazonlinux:latest
## SYSTEM SETUP
RUN yum update -y
RUN yum install -y sudo gcc g++ make git zip unzip tar bzip2 wget jq openssl uuid uidmap
RUN amazon-linux-extras install docker
## VSCODE USER Setup
RUN adduser vscode
RUN usermod -aG wheel vscode
RUN usermod -aG docker vscode
RUN echo '%vscode ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
## AWS CLI
RUN wget --quiet "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -O ~/awscliv2.zip \
    && unzip ~/awscliv2.zip \
    && ./aws/install \
    && aws --version \
    && rm aws/install \
    && rm ~/awscliv2.zip
## SAM CLI
RUN wget --quiet "https://github.com/aws/aws-sam-cli/releases/latest/download/aws-sam-cli-linux-x86_64.zip" -O ~/samcli.zip \
    && unzip ~/samcli.zip -d sam \
    && ./sam/install \
    && aws --version \
    && rm sam/install \
    && rm ~/samcli.zip 
## AWS NUKE
RUN wget https://github.com/rebuy-de/aws-nuke/releases/download/v2.14.0/aws-nuke-v2.14.0-linux-amd64 \
    && mv aws-nuke-v2.14.0-linux-amd64 /bin/aws-nuke \
    && chmod +x /bin/aws-nuke
##
##
## VSCODE USER CONFIGURATION
##
USER vscode
