# Homomorphic encryption on logistic regression
This is my cryptology project collaborated with [xuanninh1412](https://github.com/xuanninh1412).  

### Code quality checks
| Criteria | Status |
|---|---|
| codefactor |  <img src="https://www.codefactor.io/repository/github/datthinh1801/homomorphic-encryption-on-logistic-regression/badge"> |
| code quality | <a href="https://www.codacy.com/gh/datthinh1801/Homomorphic-Encryption-on-Logistic-Regression/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=datthinh1801/Homomorphic-Encryption-on-Logistic-Regression&amp;utm_campaign=Badge_Grade"><img src="https://app.codacy.com/project/badge/Grade/adf5baa0481e40caa553f59403738698"/></a> |

# Introduction
## Core concepts
Most encryption schemes consist of three functionalities: key generation, encryption, and decryption. Symmetric-key encryption schemes use the same secret key for both encryption and decryption; public-key encryption schemes use separately a public key for encryption and a secret key for decryption. Therefore, public-key encryption schemes allow anyone who knows the public key to encrypt data, but only those who know the secret key can decrypt and read the data. Symmetric-key encryption can be used for efficiently encrypting very large amounts of data, and enables secure outsourced cloud storage. Public-key encryption is a fundamental concept that enables secure online communication today, but is typically much less efficient than symmetric-key encryption.

While traditional symmetric- and public-key encryption can be used for secure storage and communication, any outsourced computation will necessarily require such encryption layers to be removed before computation can take place. Therefore, cloud services providing outsourced computation capabilities must have access to the secret keys, and implement access policies to prevent unauthorized employees from getting access to these keys.  

## Homomorphic encryption
Homomorphic encryption refers to encryption schemes that allow the cloud to compute directly on the encrypted data, without requiring the data to be decrypted first. The results of such encrypted computations remain encrypted, and can be only decrypted with the secret key (by the data owner). Multiple homomorphic encryption schemes with different capabilities and trade-offs have been invented over the past decade; most of these are public-key encryption schemes, although the public-key functionality may not always be needed.

Homomorphic encryption is not a generic technology: only some computations on encrypted data are possible. It also comes with a substantial performance overhead, so computations that are already very costly to perform on unencrypted data are likely to be infeasible on encrypted data. Moreover, data encrypted with homomorphic encryption is many times larger than unencrypted data, so it may not make sense to encrypt, e.g., entire large databases, with this technology. Instead, meaningful use-cases are in scenarios where strict privacy requirements prohibit unencrypted cloud computation altogether, but the computations themselves are fairly lightweight.  

## Microsoft SEAL
In this project, we use [Microsoft SEAL library](https://github.com/microsoft/SEAL) for implementation.  

> Microsoft SEAL is an easy-to-use open-source ([MIT licensed](https://github.com/microsoft/SEAL/blob/main/LICENSE)) homomorphic encryption library developed by the Cryptography and Privacy Research Group at Microsoft. Microsoft SEAL is written in modern standard C++ and is easy to compile and run in many different environments. For more information about the Microsoft SEAL project, see [sealcrypto.org](https://www.microsoft.com/en-us/research/project/microsoft-seal).  

Microsoft SEAL is a homomorphic encryption library that allows additions and multiplications to be performed on encrypted integers or real numbers. Other operations, such as encrypted comparison, sorting, or regular expressions, are in most cases not feasible to evaluate on encrypted data using this technology. Therefore, only specific privacy-critical cloud computation parts of programs should be implemented with Microsoft SEAL.

It is not always easy or straightfoward to translate an unencrypted computation into a computation on encrypted data, for example, it is not possible to branch on encrypted data. Microsoft SEAL itself has a steep learning curve and requires the user to understand many homomorphic encryption specific concepts, even though in the end the API is not too complicated. Even if a user is able to program and run a specific computation using Microsoft SEAL, the difference between efficient and inefficient implementations can be several orders of magnitude, and it can be hard for new users to know how to improve the performance of their computation.

Microsoft SEAL comes with two different homomorphic encryption schemes with very different properties. The BFV scheme allows modular arithmetic to be performed on encrypted integers. The CKKS scheme allows additions and multiplications on encrypted real or complex numbers, but yields only approximate results. In applications such as summing up encrypted real numbers, evaluating machine learning models on encrypted data, or computing distances of encrypted locations CKKS is going to be by far the best choice. For applications where exact values are necessary, the BFV scheme is the only choice.  

# Implementation
In this project, we implement a homomorphically logistic regression algorithm used to solve classification problems in Machine Learning. Specifically, we train a model in a homomorphic way to predict whether a patient is benign or susceptible to diabete.  

Moreover, this project is inspired by the paper [Privacy preserving based logistic regression on big data](https://www.sciencedirect.com/science/article/abs/pii/S1084804520302435).  

Homomorphic and machine learning parameters are in the below table:  

| Parameter | Value |
|---|---|
| Library | [SEAL 3.6.5](https://github.com/microsoft/SEAL/tree/3.6.5) |
| Scheme | CKKS |
| Polynomial modulus degree | 16384 bits |
| Coefficient modulus | (60, 40, 40, 40, 40, 40, 60) ~ 320 bits |
| Scale | 40 bits |
| Dataset | The Pima from the National Institude of Diabetes/Digestive/Kidney Diseases |
| Dataset size | 768 samples (10% of the original dataset) |
| Number of features | 8 |  

> All of the homomorphic parameters are chosen based on SEAL recommendations.
