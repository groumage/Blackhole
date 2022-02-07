Parsec: Toward A More Secure Cloud
==================================

Parsec is a cloud-based file storage system for confidential data sharing developed by Scille (``https://scille.eu/``). A metadata server coordinates the client’s accesses to a third party cloud storage, and provides confidential storage by letting all the data and the metadata stored in the system be encrypted with user-controlled keys. The current architecture (called Legacy Parsec) considers that the metadata server runs an honest-but-curious threat model. The version developed during my internship is a prototype of the system that aims at lifting this assumption by considering that both the metadata server and the cloud storage could be compromised by an active attacker, and both could collude with each other.

In order to achieve this safety and under the scope of the Blackhole project, we propose a prototype based on Parsec which use the ghost blockchain technique which was introduced by Hu et al. in 2020. This blockchain runs along Parsec with transparency and backgrounded clients-server-blockchain query and requests. The server periodically publishes in the blockchain (Tendermint in this prototype) a checkpoint for each metadata file of Parsec. The blockchain engine ensures that the checkpoints are stored in Byzantine fault-tolerant fashion: the strong consistency property is provided under the assumption that an attacker compromises at most one third of the node of Tendermint.

A checkpoint consist of a digest of the history (read and write operations) of a metadata file. Those checkpoints are send by the server to the blockchain and later retrieved from the blockchain by any clients. Then they are used to verify the client’s interactions with the system. By using this technique, Blackhole leverages the power of consensus provided by the ghost blockchain to provide eventual consistency even under the assumption that an attacker has compromised the metadata server.

My advisor Álvaro García-Pérez from LICIA lab at CEA List (Université Paris-Saclay) supervised this work. It was a joint collaboration with Antoine Dupré from Scille. This work and theoretical concepts (in addition with a concept of replicas for the metadata server) were presented at the workshop “Blockchain Applications in Robotics and Automation” at IROS 2021 conference in October 2021.

Cryptology end-of-study internship
==================================

My internship took place for 6 months as part of my Master degree in mathematics, computer science and applications to cryptology at the Université de paris (73th in Shanghai ranking, 2021) at the LICIA lab at CEA List, the expert in blockchain technology.

This github repo contains the work I have done during my internship. The internship has been divided into two iterations. First iteration is the branch parsec-with-blockchain which has two objectives: first show that running a blockchain within Parsec is feasible and second be familiar with source code and concepts of Parsec. Second iteration is the implementation of the verifiable history of metadata in Parsec with the help of a blockchain. You can ``git checkout`` to those branch to have further details in their README file.

I have obtained the mark 18/20 at the defense of this project, one of the best in the class.

Publications of the results
===========================

On the one hand the result have been presented at the workshop “Blockchain Applications in Robotics and Automation” at IROS 2021 conference in October 2021 by my advisor Álvaro García-Pérez. I wasn't able to present with him for personal reasons.

On the other hand, results have been published on Scille's website, the company that develop and maintain Parsec: ``https://parsec.cloud/en/la-blockchain-au-service-du-stockage-cloud-securise`` (in french).

If you are interested about discussion of this project, I'll be happy to answer you :) You can contact me with my mail: guillaume.roumage@gmail.com
