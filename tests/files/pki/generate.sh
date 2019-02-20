#!/bin/bash

CONFIG=pkiconfig.txt
set -e

gencrl()
{
	local cn=$1
	local digest=$2
	
	openssl ca -gencrl -crldays 1460 -keyfile ${cn}-key.pem -cert ${cn}-cert.pem -config $CONFIG -name crlinfo -md $digest -out ${cn}-crl.pem
}

gencrls()
{
	local digest=$2
	    
	    # Root CA issues an empty CRL
	    echo 00 > serial.txt
	    echo 01 > crlnumber.txt
	    cat /dev/null > database.txt
	    cat /dev/null > database.txt.attr
	    gencrl $1-rootca $digest
	    
	    # Informatik CA issues an empty CRL
	    echo 00 > serial.txt
	    echo 01 > crlnumber.txt
	    cat /dev/null > database.txt
	    cat /dev/null > database.txt.attr
    	gencrl $1-informatik $digest
	    
	    # CDC CA revokes cert #2
	    echo 02 > serial.txt
	    echo 01 > crlnumber.txt
	    cat /dev/null > database.txt
	    cat /dev/null > database.txt.attr

	    openssl ca -revoke $1-user2-cert.pem -crl_reason keyCompromise -config $CONFIG -name crlinfo -keyfile $1-cdc-key.pem -cert $1-cdc-cert.pem -md $digest	
		gencrl $1-cdc $digest
	    
    #pack crls
    cat *-crl.pem > $1-crls.pem
    rm *-crl.pem
}

genp12()
{
	PKI=$1
	NAME=$2
	PASS=$3

	cat $PKI-$NAME-key.pem $PKI-$NAME-cert.pem $PKI-cdc-cert.pem $PKI-informatik-cert.pem \
		| openssl pkcs12 -export -out $PKI-$NAME.p12 -password pass:$PASS -name "$PKI-$NAME key and chain"
}

function generatePKI()
{
       	echo "(Re)creating PKI for $1..."
	    # generate Root CA for 10 years
	    openssl req -x509 -config $CONFIG -nodes -days 3650 -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Praesidium/CN=Root CA $1" -newkey $2 -$3 -keyout $1-rootca-key.pem -out $1-rootca-cert.pem -set_serial 0 -extensions rootca
	    
	    #generate Intermediary CA for 8 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Informatik/CN=Informatik CA $1" -newkey $2 -keyout $1-informatik-key.pem -out $1-informatik-req.pem
	    
	    openssl x509 -req -days 2920 -set_serial 1 -in $1-informatik-req.pem -CA $1-rootca-cert.pem -CAkey $1-rootca-key.pem -extensions informatik -extfile $CONFIG -out $1-informatik-cert.pem -$3
	    
	    #generate Final CA for 6 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Kryptographie und Computeralgebra/CN=Kryptographie und Computeralgebra CA $1" -newkey $2 -keyout $1-cdc-key.pem -out $1-cdc-req.pem
	    
	    openssl x509 -req -days 2190 -set_serial 1 -in $1-cdc-req.pem -CA $1-informatik-cert.pem -CAkey $1-informatik-key.pem -extensions cdc -extfile $CONFIG -out $1-cdc-cert.pem -$3
	    
	    #generate User1 for 4 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Kryptographie und Computeralgebra/CN=User 1 $1" -newkey $2 -keyout $1-user1-key.pem -out $1-user1-req.pem
	    
	    openssl x509 -req -days 1460 -set_serial 1 -in $1-user1-req.pem -CA $1-cdc-cert.pem -CAkey $1-cdc-key.pem -extensions user1 -extfile $CONFIG -out $1-user1-cert.pem -$3
	    
	    #generate User2 for 4 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Kryptographie und Computeralgebra/CN=User 2 $1" -newkey $2 -keyout $1-user2-key.pem -out $1-user2-req.pem
	    
	    openssl x509 -req -days 1460 -set_serial 2 -in $1-user2-req.pem -CA $1-cdc-cert.pem -CAkey $1-cdc-key.pem -extensions user2 -extfile $CONFIG -out $1-user2-cert.pem -$3
	    
	    #generate Timestamp Authority for 4 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Kryptographie und Computeralgebra/CN=TSA $1" -newkey $2 -keyout $1-tsa-key.pem -out $1-tsa-req.pem
	    
	    openssl x509 -req -days 1460 -set_serial 3 -in $1-tsa-req.pem -CA $1-cdc-cert.pem -CAkey $1-cdc-key.pem -extensions tsa -extfile $CONFIG -out $1-tsa-cert.pem -$3

	    #generate Notary for 4 years
	    openssl req -config $CONFIG -nodes -subj "/C=DE/ST=Hessen/L=Darmstadt/O=TU Darmstadt/OU=Kryptographie und Computeralgebra/CN=Notary $1" -newkey $2 -keyout $1-notary-key.pem -out $1-notary-req.pem

	    openssl x509 -req -days 1460 -set_serial 4 -in $1-notary-req.pem -CA $1-cdc-cert.pem -CAkey $1-cdc-key.pem -extensions notary -extfile $CONFIG -out $1-notary-cert.pem -$3
	    
	    #remove certificate requests
	    rm *-req.pem
	    
	    #generate crls
	    gencrls $1 $3
	    	    
	    #generate PKCS12 for user1, user2, tsa and notary
	    genp12 $1 user1 $4
	    genp12 $1 user2 $4
	    genp12 $1 tsa $4
	    genp12 $1 notary $4
	    
	    #pack root cas
	    cat *-rootca-cert.pem > trust-anchors.pem
	    
	    #pack non-selfsigned-certs
	    cat $1-informatik-cert.pem $1-cdc-cert.pem $1-user*-cert.pem > $1-certs.pem 
}

usage()
{
    echo "Usage: generate.sh [simple <numberofpkis> | crl <pki index> <hashalg> | lenstra]"
    exit 0
}


#### MAIN #####
if [ "$#" -lt "1" ];
then
    usage
fi

if [ ! -e pkiconfig.txt ]
then
    echo "pkiconfig.txt does not exist"
    exit 0
fi

if [ $1 == "simple" ]
then
    #rm *-rootca-cert.pem
    
    for (( i=0; i<= $2; i++ )) ;
    do 
        generatePKI pki$i rsa:1024 sha1 1234
    done
else 
if [ $1 == "crl" ]
then
    if [ "$#" -eq "3" ];
    then
        gencrls pki$2 $3
    else
        usage
    fi
else 
if [ $1 == "crl-lenstra" ]
then
	gencrls pki0 sha256
	gencrls pki1 sha256
	gencrls pki2 sha256
	gencrls pki3 sha256
	gencrls pki4 sha256
	gencrls pki5 sha256
	gencrls pki6 sha256
	gencrls pki7 sha256
	gencrls pki8 sha256
	gencrls pki9 sha256
	gencrls pki10 sha256
	gencrls pki11 sha256
	gencrls pki12 sha256
	gencrls pki13 sha256
	gencrls pki14 sha256
	gencrls pki15 sha256
	gencrls pki16 sha384
	gencrls pki17 sha384
	gencrls pki18 sha384
	gencrls pki19 sha384
	gencrls pki20 sha384
else 
if [ $1 == "lenstra" ]
then        
	generatePKI pki0 rsa:1478 sha256 1234
	generatePKI pki1 rsa:1478 sha256 1234
	generatePKI pki2 rsa:1708 sha256 1234
	generatePKI pki3 rsa:1958 sha256 1234
	generatePKI pki4 rsa:2228 sha256 1234
	generatePKI pki5 rsa:2521 sha256 1234
	generatePKI pki6 rsa:2835 sha256 1234
	generatePKI pki7 rsa:3172 sha256 1234
	generatePKI pki8 rsa:3532 sha256 1234
	generatePKI pki9 rsa:3916 sha256 1234
	generatePKI pki10 rsa:4325 sha256 1234
	generatePKI pki11 rsa:4758 sha256 1234
	generatePKI pki12 rsa:5217 sha256 1234
	generatePKI pki13 rsa:5701 sha256 1234
	generatePKI pki14 rsa:6213 sha256 1234
	generatePKI pki15 rsa:6751 sha256 1234
	generatePKI pki16 rsa:7317 sha384 1234
	generatePKI pki17 rsa:7910 sha384 1234
	generatePKI pki18 rsa:8533 sha384 1234
	generatePKI pki19 rsa:9184 sha384 1234
	generatePKI pki20 rsa:9865 sha384 1234
fi
fi
fi
fi
