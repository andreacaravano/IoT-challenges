#
#                  Politecnico di Milano
#
#         Student: Caravano Andrea, Cantele Alberto
#
#   Last modified: 26/03/2024
#
#     Description: Dockerfile for Docker container with Base Jupyter Notebook environment

FROM quay.io/jupyter/base-notebook

#### INSTALL DEPENDENCIES ####
RUN conda update --all --yes \
    && conda install --yes notebook pyshark nest-asyncio pandas numpy scapy matplotlib scikit-learn

#### INSTALL ENVIRONMENT ####
USER root

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends tshark \
    && apt clean

#### RESTORE UNPRIVILEGED USER ####
USER ${NB_UID}