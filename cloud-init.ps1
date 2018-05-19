Write-Host 'Starting Codefresh node installation...';

$token = $args[0];
if (!$token) {
  Write-Host "The token hasn't been provided, stopping execution...";
  exit;
}

$url = 'https://cygwin.com/setup-x86_64.exe';

Write-Host 'Installing Cygwin...';

Invoke-WebRequest -Uri $url -OutFile 'C:/setup-x86_64.exe';
New-Item -ItemType directory -Path 'C:/tmp';

Start-Process "C:/setup-x86_64.exe" -NoNewWindow -Wait -PassThru -ArgumentList @('-q','-v','-n','-B','-R','C:/cygwin64','-l','C:/tmp','-s','http://mirror.pkill.info/cygwin/','-P','default,curl,openssl,unzip,procps');

Remove-Item -Path 'C:/tmp' -Force -Recurse -ErrorAction Ignore;
Start-Process "C:/cygwin64/bin/cygcheck.exe" -NoNewWindow -Wait -PassThru -ArgumentList @('-c');

Write-Host 'Finished installing Cygwin...';

Write-Host 'Installing Docker-EE...';

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
Install-Module DockerProvider -Force;
Install-Package Docker -ProviderName DockerProvider -RequiredVersion 17.10.0-ee-preview-3 -Force;
Write-Host 'Finished installing Docker-EE...';

Write-Host 'Opening a local firewall port for the dockerd...';
netsh advfirewall firewall add rule name="DockerD 2376" dir=in action=allow protocol=TCP localport=2376;

#Generating the shell script file

$script_path = ($pwd.Path + '\cloud-init.sh').Replace('\', '/');

$script_contents = @'
#!/bin/bash
#
echo -e "The script installs docker and registers node in codefresh.io \n\
Please ensure:
  1. Supported systems: Ubuntu 14+ | Debian 8+ | RHEL/Centos/Oracle 7+
  2. The script is running by admin user ( root or by sudo $(basename $0) )
  3. Port tcp:2376 should be open for codefresh whitelist addresses

" 

API_HOST=https://g.codefresh.io/api/nodes

#---
fatal() {
   echo "ERROR: $1"
   exit 1
}

while [[ $1 =~ ^(-(g|t|y)|--(gen-certs|token|yes|ip|iface|dns-name|install|no-install|restart|no-restart)) ]]
do
  key=$1
  value=$2

  case $key in
    -y|--yes)
        YES="true"
      ;;
    -g|--gen-certs)
        GENERATE_CERTS="true"
      ;;
    -t|--token)
        TOKEN="$value"
        shift
      ;;
    --ip)
        ## IP Address
        IP="$value"
        shift
      ;;
    --iface)
        ## Net interface to take IP
        IFACE="$value"
        shift
      ;;
    --dns-name)
        DNSNAME="$value"
        shift
      ;;
    --restart)
        RESTART_DOCKER="true"
      ;;
    --no-restart)
        RESTART_DOCKER="false"
      ;;
  esac
  shift # past argument or value
done


TOKEN=${TOKEN:-$1}
[[ -z "$TOKEN" ]] && fatal "Missing token"


if [[ -z "$IP" ]]; then
    echo "Determine default IP ..."

    if [[ -n "$IFACE" && ! "$IFACE" == 'public' ]]; then
       DEFAULT_IP=$(/sbin/ip -4 -o addr show scope global | awk -v iface=$IFACE '$2==iface { sub(/\/.*/,"", $4) ; print $4 }')
    else
        ## Get Public IP
        cnt=0
        while [[ $cnt -lt 20 ]]
        do
           DEFAULT_IP=$(timeout 3 curl ident.me 2>/dev/null || timeout 3 curl ipecho.net/plain 2>/dev/null || timeout 3 curl whatismyip.akamai.com 2>/dev/null)
           [[ -n "${DEFAULT_IP}" ]] && break
           (( cnt ++ ))
           sleep 3
        done
    fi

    if [[ ! "$YES" == 'true' ]]; then
        echo -e "Enter the IP Address of the node for incoming connection from Codefresh (port tcp:2376)
    ${DEFAULT_IP} - default
$(/sbin/ip -4 -o addr show scope global | awk '{gsub(/\/.*/,"",$4); print "    "$4}' | sort)\n"
        read -p "IP of the node - default ${DEFAULT_IP}: " IP
    fi

    if [[ -z "$IP" ]]; then
      IP="${DEFAULT_IP}"
    fi
fi

if [[ -z "$DNSNAME" && ! "$YES" == 'true' ]]; then
  read -p "Enter DNS name of the node (optional): " DNSNAME
fi
DNSNAME=${DNSNAME:-$IP}



TMPDIR=/tmp/codefresh/
TMP_VALIDATE_RESPONSE_FILE=$TMPDIR/validate-RESPONSE
TMP_VALIDATE_HEADERS_FILE=$TMPDIR/validate-headers.txt

TMP_CERTS_FILE_ZIP=$TMPDIR/cf-certs.zip
TMP_CERTS_HEADERS_FILE=$TMPDIR/cf-certs-response-headers.txt
CERTS_DIR=/etc/ssl/codefresh
SRV_TLS_KEY=${CERTS_DIR}/cf-server-key.pem
SRV_TLS_CSR=${CERTS_DIR}/cf-server-cert.csr
SRV_TLS_CERT=${CERTS_DIR}/cf-server-cert.pem
SRV_TLS_CA_CERT=${CERTS_DIR}/cf-ca.pem
mkdir -p $TMPDIR $CERTS_DIR



echo -e "\n------------------\nValidate node ... "
echo "{\"ip\": \"$IP\", \"dnsname\": \"${DNSNAME}\"}" > ${TMPDIR}/validate_req.json
VALIDATE_STATUS=$(curl -sSL -d @${TMPDIR}/validate_req.json  -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
      -o ${TMP_VALIDATE_RESPONSE_FILE} -D ${TMP_VALIDATE_HEADERS_FILE} -w '%{http_code}' $API_HOST/validate )
echo "Validate Node request completed with HTTP_STATUS_CODE=$VALIDATE_STATUS"
if [[ $VALIDATE_STATUS != 200 ]]; then
   echo "ERROR: Node Validation failed"
   if [[ -f ${TMP_VALIDATE_RESPONSE_FILE} ]]; then
     mv ${TMP_VALIDATE_RESPONSE_FILE} ${TMP_VALIDATE_RESPONSE_FILE}.error
     cat ${TMP_VALIDATE_RESPONSE_FILE}.error
   fi
   exit 1
fi

echo "Validate RESPONSE: "
cat ${TMP_VALIDATE_RESPONSE_FILE}
source ${TMP_VALIDATE_RESPONSE_FILE}

[[ -z "$CF_NODE_NAME" ]] && fatal "Validation failed - cannot find CF_NODE_NAME"

echo -e "\n------------------\nGenerating docker server tls certificates ... "
if [[ "$GENERATE_CERTS" == 'true' || ! -f ${SRV_TLS_CERT} || ! -f ${SRV_TLS_KEY} || ! -f ${SRV_TLS_CA_CERT} ]]; then
  openssl genrsa -out $SRV_TLS_KEY 4096 || fatal "Failed to generate openssl key " 
  openssl req -subj "/CN=${CF_NODE_NAME}.codefresh.io" -new -key $SRV_TLS_KEY -out $SRV_TLS_CSR  || fatal "Failed to generate openssl csr "
  GENERATE_CERTS=true
  CSR=$(sed ':a;N;$!ba;s/\n/\\n/g' ${SRV_TLS_CSR})
else  
  echo "Certificates already exist in $CERTS_DIR - Do not generate certificates"
fi

echo "{\"ip\": \"${IP}\", \"serverAuthIps\": \"${IP}\", \"dnsname\": \"${DNSNAME}\", \
   \"csr\": \"${CSR}\" }" > ${TMPDIR}/sign_req.json

if [[ $GENERATE_CERTS == 'true' ]]; then
  rm -fv ${TMP_CERTS_HEADERS_FILE} ${TMP_CERTS_FILE_ZIP}
  SIGN_STATUS=$(curl -sSL -d @${TMPDIR}/sign_req.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" -H "Expect: " \
        -o ${TMP_CERTS_FILE_ZIP} -D ${TMP_CERTS_HEADERS_FILE} -w '%{http_code}' $API_HOST/sign )
        
  echo "Sign request completed with HTTP_STATUS_CODE=$SIGN_STATUS"
  if [[ $SIGN_STATUS != 200 ]]; then
     echo "ERROR: Cannot sign certificates"
     if [[ -f ${TMP_CERTS_FILE_ZIP} ]]; then
       mv ${TMP_CERTS_FILE_ZIP} ${TMP_CERTS_FILE_ZIP}.error
       cat ${TMP_CERTS_FILE_ZIP}.error
     fi
     exit 1
  fi
  unzip -o -d ${CERTS_DIR}/  ${TMP_CERTS_FILE_ZIP} || fatal "Failed to unzip certificates to ${CERTS_DIR} "
  RESTART_DOCKER=${RESTART_DOCKER:-'true'}


  # Generate internal certs (ICA)
    ICA_PASS=$RANDOM
    ICA_PASS_FILE=${CERTS_DIR}/i-capass

    ICA_KEY=${CERTS_DIR}/i-ca-key.pem
    ICA=${CERTS_DIR}/i-ca.pem
    IEXTFILE=${CERTS_DIR}/i-extfile
    ICERT_CSR=${CERTS_DIR}/i-cert.csr
    ICERT_KEY=${CERTS_DIR}/i-key.pem
    ICERT=${CERTS_DIR}/i-cert.pem

    ICA_SUBJECT="/CN=internal.cf-cd.com"

    echo "CA_PASS = $ICA_PASS " > "$ICA_PASS_FILE"

    echo "--- Generate internal ca-key.pem"
    openssl genrsa -aes256 -out "$ICA_KEY" -passout pass:"$ICA_PASS"

    echo "--- Generate internal ca.pem"
    openssl req -new -x509 -days 1096 -key "$ICA_KEY" -sha256 -out "$ICA" -subj "${ICA_SUBJECT}" -passin pass:"$ICA_PASS"


    echo "--- Generate internal key.pem"
    openssl genrsa -out "$ICERT_KEY" 4096

    echo "--- generate internal csr "
    openssl req -subj "${ICA_SUBJECT}" -sha256 -new -key "${ICERT_KEY}" -out "${ICERT_CSR}"

    echo "--- create internal ca extfile"
    echo "extendedKeyUsage=clientAuth" > "$IEXTFILE"

    echo "--- sign internal certificate ${ICERT} "
    openssl x509 -req -days 1096 -sha256 -in "$ICERT_CSR" -CA "$ICA" -CAkey "$ICA_KEY" \
    -CAcreateserial -out "$ICERT" -extfile "$IEXTFILE" -passin pass:"$ICA_PASS" || fatal "Failed to sign internal certificate"

    echo "--- Appending Internal CA file to dockerd tlscacert ${SRV_TLS_CA_CERT} "
    cat ${ICA} >> ${SRV_TLS_CA_CERT}

fi
   
  
   echo "--- Configuring the docker daemon..."
   
   DOCKERD_CFG='{"hosts":["tcp://0.0.0.0:2376","npipe:////./pipe/codefresh/docker_engine","npipe://"],"tlsverify":true,"tlscacert":"C:/cygwin64/etc/ssl/codefresh/cf-ca.pem","tlscert":"C:/cygwin64/etc/ssl/codefresh/cf-server-cert.pem","tlskey":"C:/cygwin64/etc/ssl/codefresh/cf-server-key.pem"}'
   
   mkdir C:/ProgramData/Docker/
   mkdir C:/ProgramData/Docker/config
   echo $DOCKERD_CFG > C:/ProgramData/Docker/config/daemon.json

   echo -e "\n------------------\nRegistering Docker node ... "
   
   CPU_CORES=$(cat /proc/cpuinfo | grep "^processor" | wc -l)
   CPU_MODEL=$(cat /proc/cpuinfo | awk -F ': ' '/model name/{print $2}' | head -n1)
   RAM="$(free -m | awk '/Mem:/{print $2}')M"
   SYSTEM_DISK=$(/bin/df -h / | awk 'NR==2{print $2}')
   CREATION_DATE=$(date +"%Y-%m-%d %H:%M")
   OS_ID=windows #$(. /etc/os-release 2>/dev/null && echo ${ID} || echo linux)
   OS_VERSION=1709 #$(. /etc/os-release 2>/dev/null && echo ${VERSION_ID} || echo "")
   OS_NAME=windows #$(. /etc/os-release 2>/dev/null && echo ${PRETTY_NAME:-$ID} || echo linux)
   HOSTNAME=$(hostname)

   SYSTEM_DATA="{\"cpu_cores\": \"${CPU_CORES}\",
  \"cpu_model\": \"${CPU_MODEL}\",
  \"ram\": \"${RAM}\",
  \"system_disk\": \"${SYSTEM_DISK}\",
  \"os_id\": \"$OS_ID\",
  \"os_version\": \"$OS_VERSION\",
  \"os_name\": \"$OS_NAME\",
  \"hostname\": \"$HOSTNAME\",
  \"creation_date\": \"${CREATION_DATE}\"}"  

   REGISTER_DATA="{\"ip\": \"${IP}\",
  \"dnsname\": \"${DNSNAME}\",
  \"systemData\": "${SYSTEM_DATA}"}"
   
  echo "${REGISTER_DATA}" > ${TMPDIR}/register_data.json   
  
  rm -f ${TMPDIR}/register.out ${TMPDIR}/register_RESPONSE_headers.out
  REGISTER_STATUS=$(curl -sSL -d @${TMPDIR}/register_data.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
        -o ${TMPDIR}/register.out -D ${TMPDIR}/register_RESPONSE_headers.out -w '%{http_code}' $API_HOST/register )   

  echo "Registration request completed with HTTP_STATUS_CODE=$REGISTER_STATUS"
  if [[ $REGISTER_STATUS == 200 ]]; then
     echo -e "Node has been successfully registered with Codefresh\n------"
  else
     echo "ERROR: Failed to register docker node with Codefresh"
     [[ -f ${TMPDIR}/register.out ]] && cat ${TMPDIR}/register.out
     echo -e "\n----\n"
     exit 1
  fi
'@

[IO.File]::WriteAllLines($script_path, $script_contents);

Write-Host 'Running the node installation shell script...';

C:\cygwin64\bin\bash -l -c "sed -i 's/\r$//' $script_path" # necessary for cygwin
C:\cygwin64\bin\bash -l -c "$script_path $token"

# Write down the scripts needed to be run after rebooting to finish the installation and make them start on logon

$pullImagesScript = @'

$DockerDaemon = $(docker info)

if (![string]::IsNullOrEmpty($DockerDaemon)) {

  docker pull codefresh/cf-container-logger:0.0.18-windows;
  docker pull codefresh/cf-docker-pusher:v2-windows;
  docker pull codefresh/cf-docker-puller:v2-windows;
  docker pull codefresh/cf-docker-builder:v11-windows;

  docker pull codefresh/cf-git-cloner:v3-windows;
  docker pull codefresh/cf-compose:windows;
  docker pull codefresh/cf-deploy-kubernetes:v1.0-windows;
  docker pull codefresh/fs-ops:windows;

  schtasks /delete /f /tn "Finish Codefresh installation";

  rm C:\cf-finish-installation.ps1;
  rm C:\BatchJob.bat;
 
} else {

  Write-host "Installation failed: Unable to communicate with Docker daemon, most likely is not running. Rebooting might help..." -ForegroundColor Red
  Write-host "Reboot the node now?. (Default is No)" -ForegroundColor Yellow 
    $Readhost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) 
     { 
       Y {Write-host "Yes, reboot"; $reboot=$true} 
       N {Write-Host "No, do not reboot"; $reboot=$false} 
       Default {Write-Host "Do not reboot"; $reboot=$false} 
     }
}

'@

[IO.File]::WriteAllLines("C:\cf-finish-installation.ps1", $pullImagesScript)

$BatchJob=@'

powershell -command "C:\cf-finish-installation.ps1"

'@

[IO.File]::WriteAllLines("C:\BatchJob.bat", $BatchJob);

schtasks /create /f /tn "Finish Codefresh installation" /tr C:\BatchJob.bat /sc onlogon /ru $env:UserName;

Write-host "Reboot is required to compete the installation. Reboot the node now?(Default is No)" -ForegroundColor Yellow 
    $Readhost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) 
     { 
       Y {Write-host "Yes, reboot"; $reboot=$true} 
       N {Write-Host "No, do not reboot"; $reboot=$false} 
       Default {Write-Host "Default, skipping reboot"; $reboot=$false} 
     }


if ($reboot -eq $True) { shutdown -r -t 0 }
