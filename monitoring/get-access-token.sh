#!/bin/bash

IAM_USER='your_iam_user'
IAM_PASSWORD='your_iam_password'


if [[ -z ${IAM_USER} ]]; then
  read -p "Username: " IAM_USER
fi

#echo -ne "Password:"
#read -s IAM_PASSWORD
echo

result=$(curl -s -L \
  -d grant_type=password \
  -d client_id=your_application_client_id \
  -d client_secret=your_application_client_secret \
  -d username=${IAM_USER} \
  -d password=${IAM_PASSWORD} \
  ${IAM_ENDPOINT:-https://iam-test.indigo-datacloud.eu/token})

if [[ $? != 0 ]]; then
  echo "Error!"
  echo $?
  echo $result
  exit 1
fi

echo $result

access_token=$(echo $result | jq -r .access_token)

#echo "export IAM_ACCESS_TOKEN=\"${access_token}\""
