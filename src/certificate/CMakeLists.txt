cmake_minimum_required(VERSION 2.8)

set(SOURCE_FILES
        AccessDescription.cpp
        AuthorityInformationAccessExtension.cpp
        AuthorityKeyIdentifierExtension.cpp
        BasicConstraintsExtension.cpp
        Certificate.cpp
        CertificateBuilder.cpp
        CertificatePoliciesExtension.cpp
        CertificateRequest.cpp
        CertificateRequestFactory.cpp
        CertificateRequestSPKAC.cpp
        CertificateRevocationList.cpp
        CertificateRevocationListBuilder.cpp
        CertPathValidator.cpp
        CRLDistributionPointsExtension.cpp
        CRLNumberExtension.cpp
        DistributionPoint.cpp
        DistributionPointName.cpp
        ExtendedKeyUsageExtension.cpp
        Extension.cpp
        GeneralName.cpp
        GeneralNames.cpp
        IssuerAlternativeNameExtension.cpp
        KeyUsageExtension.cpp
        ObjectIdentifier.cpp
        ObjectIdentifierFactory.cpp
        PolicyInformation.cpp
        PolicyQualifierInfo.cpp
        RDNSequence.cpp
        RevokedCertificate.cpp
        SubjectAlternativeNameExtension.cpp
        SubjectInformationAccessExtension.cpp
        SubjectKeyIdentifierExtension.cpp
        UserNotice.cpp)

add_library(certificate ${SOURCE_FILES})
