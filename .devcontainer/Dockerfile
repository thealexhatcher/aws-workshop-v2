FROM amazonlinux:latest
## SYSTEM SETUP
RUN yum update -y
RUN yum install -y sudo gcc g++ make git zip unzip tar bzip2 wget jq openssl uuid python pip docker
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
## AWS NUKE
RUN AWS_NUKE_LATEST=$(curl -skL https://github.com/rebuy-de/aws-nuke/releases/latest | xmllint -html -xpath '//a[contains(@href, "releases")]/text()' - 2> /dev/null | grep -P 'v' | sed -e 's/^[ \t]*//') \
    && wget https://github.com/rebuy-de/aws-nuke/releases/download/$AWS_NUKE_LATEST/aws-nuke-$AWS_NUKE_LATEST-linux-amd64.tar.gz --no-check-certificate \
    && tar -xf aws-nuke-$AWS_NUKE_LATEST-linux-amd64.tar.gz \
    && mv aws-nuke-$AWS_NUKE_LATEST-linux-amd64 /bin/aws-nuke \
    && chmod +x /bin/aws-nuke
## VSCODE USER CONFIGURATION
##
USER vscode
#### INSTALL POETRY 
RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH "/home/vscode/.local/bin:$PATH"
RUN poetry config cache-dir --unset \
    && poetry config virtualenvs.path --unset \
    && poetry config installer.parallel true \ 
    && poetry config virtualenvs.create true \
    && poetry config virtualenvs.in-project true
#### START VENV ON TERMINAL STARTUP
RUN echo "poetry install --no-root && source .venv/bin/activate" >> ~/.bashrc