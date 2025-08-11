#
#                  Politecnico di Milano
#
#         Student: Caravano Andrea, Cantele Alberto
#
#   Last modified: 23/04/2025
#
#     Description: Dockerfile for Docker container with Base Jupyter Notebook environment for LoRaSim

FROM --platform=linux/amd64 quay.io/jupyter/base-notebook

#### INSTALL DEPENDENCIES ####
RUN conda update --all --yes \
    && conda install --yes notebook nest-asyncio pandas numpy scapy matplotlib scikit-learn

#### INSTALL DEPENDENCIES ####
USER root

# Python2 is no more available for Ubuntu 24.04, downloading and installing manually...
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl wget tar sed \
    && cd /tmp/ \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python-defaults/python2_2.7.18-3_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python2.7/python2.7_2.7.18-13ubuntu1_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python-defaults/libpython2-stdlib_2.7.18-3_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python2.7/libpython2.7-stdlib_2.7.18-13ubuntu1_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python-defaults/python2-minimal_2.7.18-3_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python2.7/python2.7-minimal_2.7.18-13ubuntu1_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python2.7/libpython2.7-minimal_2.7.18-13ubuntu1_amd64.deb \
    && wget http://security.ubuntu.com/ubuntu/pool/universe/p/python-stdlib-extensions/python-tk_2.7.18-1build1_amd64.deb \
    && apt-get -y install --no-install-recommends ./*.deb \
    && curl -o get-pip.py https://bootstrap.pypa.io/pip/2.7/get-pip.py

#### INSTALL LoRaSim AND ITS DEPENDENCIES ####
RUN curl -o lorasim.tgz https://www.lancaster.ac.uk/scc/sites/lora/lorasim-20170710.tgz \
    && tar -xvf lorasim.tgz \
    && mkdir /lorasim/ \
    && mv ./lorasim/* /lorasim/

#### UPDATE LoRaSim WITH ITS MODIFIED VERSION ####
RUN cp /lorasim/loraDir.py /lorasim/loraDir-old.py \
    && cp /lorasim/loraDirMulBS.py /lorasim/loraDirMulBS-old.py \
    # Remove lines 116 and 117 (corresponding to the collisions sub-estimation)
    && sed -i '116,+1d;' /lorasim/loraDir-old.py \
    # Replace natural logarithms with base-10 logarithm
    && sed -i 's/math.log10/math.log/g' /lorasim/loraDir-old.py \
    # Remove lines 107 and 108 (corresponding to the collisions sub-estimation)
    && sed -i '107,+1d;' /lorasim/loraDirMulBS-old.py \
    # Replace natural logarithms with base-10 logarithm
    && sed -i 's/math.log10/math.log/g' /lorasim/loraDirMulBS-old.py \
    # Permissions setup
    && chmod -R 777 /lorasim/

#### PATH SETUP ####
ENV PATH="$PATH:/home/$NB_USER/.local/bin"

#### INSTALL LoRaSim DEPENDENCIES ####
# Unprivileged notebook user
USER ${NB_UID}

RUN python2 /tmp/get-pip.py \
    && pip2 install -r '/lorasim/requirements.txt'

#### CLEAN UP ####
USER root

# Generally, Dev Container Features assume that the non-root user (in this case jovyan)
# is in a group with the same name (in this case jovyan). So we must first make that so.
# (see https://github.com/devcontainers-community/templates-jupyter-datascience-notebooks/)
RUN groupadd jovyan \
    && usermod -g jovyan -a -G users jovyan

RUN rm -rf /tmp/*

#### RESTORE UNPRIVILEGED USER ####
USER ${NB_UID}