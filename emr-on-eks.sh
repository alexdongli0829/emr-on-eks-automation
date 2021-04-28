#!/bin/bash
#update 2021-04-29
set -e
#clear the record file
truncate -s 0 record.txt

#check the subnet public/private
check_subnet_public(){
	region=$2
        vpc_id=$(aws ec2 describe-subnets --filter Name=subnet-id,Values=[$1] --query Subnets[].VpcId --output text --region $region)
        #check if there is any specific routetable for the subnet
        has_associate_rt=$(aws ec2 describe-route-tables --filters Name=association.subnet-id,Values=[$1] --query RouteTables[].Routes[].GatewayId --output text --region $2 | wc -l)
        #if there is speical rt associated, check if the igw there

        if [ $has_associate_rt -ge 1 ]; then
                igw_check_subnet_level=$(aws ec2 describe-route-tables --filters Name=association.subnet-id,Values=[$1] --query RouteTables[].Routes[].GatewayId --output text --region $2 | grep "igw-" |wc -l)
                if [ $igw_check_subnet_level -ge 1 ]; then
                        echo "public"
                else
                        echo "prvate"
                fi
        #if there is no associate rt, check the vpc main routeable and confirm if the igw there
        else
                igw_check_vpc_level=$(aws ec2 describe-route-tables --filters Name=vpc-id,Values=[$vpc_id] --filter Name=association.main,Values=[true] --region $2 --query RouteTables[].Routes[].GatewayId --output text | grep "igw-" |wc -l)
                if [ $igw_check_vpc_level -ge 1 ]; then
                        echo "public"
                else
                        echo "private"
                fi
        fi
}


#create the role for the amp
#https://docs.aws.amazon.com/prometheus/latest/userguide/set-up-irsa.html
create_amp_role(){

        CLUSTER_NAME=$clustername
        #prometheus namespace $prometheus-ns
        SERVICE_ACCOUNT_NAMESPACE=$prometheus_ns
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
        OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME --region $region --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")
        SERVICE_ACCOUNT_AMP_INGEST_NAME=amp-iamproxy-ingest-service-account
        SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE=amp-iamproxy-ingest-role
        SERVICE_ACCOUNT_IAM_AMP_INGEST_POLICY=AMPIngestPolicy
        #
        # Set up a trust policy designed for a specific combination of K8s service account and namespace to sign in from a Kubernetes cluster which hosts the OIDC Idp.
        #
cat <<EOF > TrustPolicy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_AMP_INGEST_NAME}"
        }
      }
    }
  ]
}
EOF

        # Set up the permission policy that grants ingest (remote write) permissions for all AMP workspaces
        #
cat <<EOF > PermissionPolicyIngest.json
{
  "Version": "2012-10-17",
   "Statement": [
       {"Effect": "Allow",
        "Action": [
           "aps:RemoteWrite",
           "aps:GetSeries",
           "aps:GetLabels",
           "aps:GetMetricMetadata"
        ],
        "Resource": "*"
      }
   ]
}
EOF

        function getRoleArn() {
          OUTPUT=$(aws iam get-role --role-name $1 --query 'Role.Arn' --output text 2>&1)

          # Check for an expected exception
          if [[ $? -eq 0 ]]; then
            echo $OUTPUT
          elif [[ -n $(grep "NoSuchEntity" <<< $OUTPUT) ]]; then
            echo ""
          else
            >&2 echo $OUTPUT
            return 1
          fi
        }

        #
        # Create the IAM Role for ingest with the above trust policy
        #
        SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE_ARN=$(getRoleArn $SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE)
        if [ "$SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE_ARN" = "" ];
        then
          #
          # Create the IAM role for service account
          #
          SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE_ARN=$(aws iam create-role \
          --role-name $SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE \
          --assume-role-policy-document file://TrustPolicy.json \
          --query "Role.Arn" --output text)
          #
          # Create an IAM permission policy
          #
          SERVICE_ACCOUNT_IAM_AMP_INGEST_ARN=$(aws iam create-policy --policy-name $SERVICE_ACCOUNT_IAM_AMP_INGEST_POLICY \
          --policy-document file://PermissionPolicyIngest.json \
          --query 'Policy.Arn' --output text)
          #
          # Attach the required IAM policies to the IAM role created above
          #
          aws iam attach-role-policy \
          --role-name $SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE \
          --policy-arn $SERVICE_ACCOUNT_IAM_AMP_INGEST_ARN
        else
          echo "$SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE_ARN IAM role for ingest already exists, just update the trust"

          aws iam update-assume-role-policy \
          --role-name $SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE \
          --policy-document file://TrustPolicy.json
        fi

        echo $SERVICE_ACCOUNT_IAM_AMP_INGEST_ROLE_ARN
        #
        # EKS cluster hosts an OIDC provider with a public discovery endpoint.
        # Associate this IdP with AWS IAM so that the latter can validate and accept the OIDC tokens issued by Kubernetes to service accounts.
        # Doing this with eksctl is the easier and best approach.
        #
        eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --region $region --approve

}



launch_eks_cluster(){
	select_result=$(eksctl get clusters -o json --region $region| jq -r --arg clustername "$clustername" '.[]|select(.metadata.name==$clustername)')
	if [[ -z $select_result ]]; then
		eks_create_string="eksctl create cluster --name $clustername --region $region --nodegroup-name $nodegroup_name --node-type $instance_type --nodes-min $min_nodenumber --nodes-max $max_nodenumber"

		#if there is keyname, enable the ssh access
		if [[ -n $keyname ]];then
			eks_create_string=$eks_create_string" --ssh-access --ssh-public-key $keyname"
		fi

		#if customer want to launch into existing vpc, then check the vpc setting
		if [ $existing_vpc == "yes" ]; then
			if [[ -n $private_subnet ]]; then
				eks_create_string=$eks_create_string" --vpc-private-subnets $private_subnet"
			fi

			if [[ -n $public_subnet ]]; then
				eks_create_string=$eks_create_string" --vpc-public-subnets $public_subnet"
			else
				eks_create_string=$eks_create_string" --node-private-networking"
			fi
		fi

		echo "eks_create_cli:"$eks_create_string >> record.txt

		#return eks create string
		#print the create string out
		eval $eks_create_string
	fi

}



launch_emr_cluster(){

	ns_exist=$(kubectl get ns $emr_namespace  2>&1 | grep "not found" |wc -l)
	if [ $ns_exist -eq 1 ]; then
        	#create a namespace for the emr on eks
	        kubectl create namespace $emr_namespace
	fi

        #approve the cluster OIDC
        eksctl utils associate-iam-oidc-provider --cluster $clustername --region $region --approve


	service_role_check=$(aws iam list-roles --path-prefix "/aws-service-role/emr-containers.amazonaws.com/" | jq -r '.Roles[]|select(.RoleName=="AWSServiceRoleForAmazonEMRContainers")')
	if [[ -z $service_role_check ]]; then
		aws iam create-service-linked-role --aws-service-name emr-containers.amazonaws.com
	fi


        #create the ID mapping between the EMR service role AWSServiceRoleForAmazonEMRContainers and EKS user/group
        eksctl create iamidentitymapping \
            --cluster $clustername \
            --namespace $emr_namespace\
            --service-name "emr-containers" \
            --region $region


        #update the trust policy for the role which will be used in spark job and trust the eks cluster
        aws emr-containers update-role-trust-policy \
               --cluster-name $clustername \
               --namespace $emr_namespace\
               --region $region \
               --role-name $rolename

	#check if the cluster existing
	id=$(aws emr-containers list-virtual-clusters --container-provider-id $clustername --state RUNNING --region $region|jq --arg ns $emr_namespace '.virtualClusters[]|select(.containerProvider.info.eksInfo.namespace==$ns)' | jq -r '.id')
	#if did not find the id, then create the cluster
	if [[ -z $id ]]; then
        	#emr cluster create string
		emr_create_string="aws emr-containers create-virtual-cluster --name $emrclustername --container-provider '{\"id\": \"$clustername\",\"type\": \"EKS\",\"info\": {\"eksInfo\": {\"namespace\": \"$emr_namespace\"}}}' --region $region"
		
		echo "emr_cmd:"$emr_create_string >>record.txt
		echo "creating EMR cluster:"$emrclustername >&2
		id=$(eval $emr_create_string | jq -r '.id')
		state=$(aws emr-containers describe-virtual-cluster --id $id --region $region|jq -r '.virtualCluster.state')
		while [ $state != "RUNNING" ];
		do
			if [ $state != "CREATING" ];then
				echo "failed to create the cluster">&2
				exit 1
			fi
			sleep 5
			echo "waiting emr cluster to be avaiable"
			state=$(aws emr-containers describe-virtual-cluster --id $id --region $region|jq -r '.virtualCluster.state')
		done
	fi

        echo "emr_cluster_id:"$id>>record.txt

}


create_amp(){

        echo "create workspace" >&2
        result=$(aws amp create-workspace --alias $ws_alias --region $region)
        workspaceid=$(echo $result | jq -r '.workspaceId')
        state=$(aws amp describe-workspace --workspace-id $workspaceid --query workspace.status.statusCode --output text --region $region)
        while [ $state != "ACTIVE" ];
        do
                echo "waiting for workspace to be active" >&2
                state=$(aws amp describe-workspace --workspace-id $workspaceid --query workspace.status.statusCode --output text --region $region)
                sleep 2
        done

        truncate -s 0 amp_ingest_override_values.yaml

cat << EoF > amp_ingest_override_values.yaml
serviceAccounts:
    server:
        name: "amp-iamproxy-ingest-service-account"
        annotations:
            eks.amazonaws.com/role-arn: "arn:aws:iam::$accountId:role/amp-iamproxy-ingest-role"
server:
    sidecarContainers:
        aws-sigv4-proxy-sidecar:
            image: public.ecr.aws/aws-observability/aws-sigv4-proxy:1.0
            args:
            - --name
            - aps
            - --region
            - $region
            - --host
            - aps-workspaces.$region.amazonaws.com
            - --port
            - :8005
            ports:
            - name: aws-sigv4-proxy
              containerPort: 8005
    statefulSet:
        enabled: "true"
    remoteWrite:
        - url: http://localhost:8005/workspaces/$workspaceid/api/v1/remote_write
EoF

        echo $workspaceid
}

install_promethus_on_eks(){

	#check if the namespace is there
	ns_exist=$(kubectl get ns $prometheus_ns 2>&1 | grep "not found" |wc -l)
        if [ $ns_exist -eq 1 ]; then
                #create a namespace for the emr on eks
                kubectl create namespace $prometheus_ns
        fi


	#check the chart if its there
	chart_check=$(helm list -n $prometheus_ns -o json | jq -r --arg name "$prometheus_chart_name" '.[]|select(.name==$name)')
	if [[ -z $chart_check ]]; then
		helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
		helm install $prometheus_chart_name prometheus-community/prometheus --namespace $prometheus_ns -f ./amp_ingest_override_values.yaml
	fi
}

######################################################
#main function start
####################################################
#INPUT parameters

read -p "Using Existing EKS cluster? (y/n)[n]: " useexisting
useexisting=${useexisting:-n}
echo $useexisting
echo "use existing cluster:"$useexisting>> record.txt


read -p "EKS Cluster Name: [emr-on-eks]: " clustername
clustername=${clustername:-emr-on-eks}
echo $clustername
echo "clustername:"$clustername >> record.txt


default_accountId=$(aws sts get-caller-identity --output text --query Account)
read -p "EMR account: [$default_accountId]: " accountId
accountId=${accountId:-"$default_accountId"}
echo $accountId
echo "accountId:"$accountId>> record.txt

read -p "region: [us-east-1]: " region
region=${region:-us-east-1}
echo $region
echo "region:"$region>> record.txt

if [ $useexisting == "n" ]; then

	read -p "ec2 Key: " keyname
	keyname=${keyname:-}
	echo $keyname
	echo "keyname:"$keyname>> record.txt

	read -p "Instance Type[m5.xlarge]: " instance_type
	instance_type=${instance_type:-m5.xlarge}
	echo $instance_type
	echo "instance_type:"$instance_type>> record.txt


	default_groupname="group-"$(echo $instance_type |sed 's/\./-/g')
	read -p "NodeGroup Name[$default_groupname]: " nodegroup_name
	nodegroup_name=${nodegroup_name:-$default_groupname}
	echo $nodegroup_name
	echo "nodegroup_name:"$nodegroup_name>> record.txt


	read -p "Launch Into Existing VPC(yes/no)?[no]: " existing_vpc
	existing_vpc=${existing_vpc:-no}
	echo $existing_vpc
	echo "existing_vpc:"$existing_vpc>> record.txt

	if [ $existing_vpc == "yes" ]; then
		default_vpc=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=[true] --query Vpcs[0].VpcId --output text --region $region)
		read -p "VPC ID[default VPC: $default_vpc]: " vpc_id
		vpc_id=${vpc_id:-$default_vpc}
		echo $vpc_id
		echo "vpc_id:"$vpc_id>> record.txt

		default_subnet_list=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=[$vpc_id] --query Subnets[].SubnetId --output text --region $region)

		private_subnet_list=()
		public_subnet_list=()

		for f in $default_subnet_list; do
			net=$(check_subnet_public $f $region);
			if [ $net == "public" ]; then
				public_subnet_list+=$f","
			else
				private_subnet_list+=$f","
			fi
		done



		read -p "Private Subnet Input(use commar as separator, private subnet list:)[${private_subnet_list::-1}]: " private_subnet
		private_subnet=${private_subnet}
		echo "private subnet you choose:"$private_subnet
		echo "private_subnet:"$private_subnet>> record.txt

		read -p "Public Subnet Input(use commar as separator, public subnet list:)[${public_subnet_list::-1}]: " public_subnet
		public_subnet=${public_subnet}
		echo "public subnet you choose:"$public_subnet
		echo "public_subnet:"$public_subnet>> record.txt
	fi

	read -p "Min Node Number[2]: " min_nodenumber
	min_nodenumber=${min_nodenumber:-2}
	echo $min_nodenumber
	echo "min_nodenumber:"$min_nodenumber>> record.txt


	read -p "Max Node Number[5]: " max_nodenumber
	max_nodenumber=${max_nodenumber:-5}
	echo $max_nodenumber
	echo "max_nodenumber:"$max_nodenumber>> record.txt
else
	aws eks update-kubeconfig --name $clustername --region $region
fi



#EMR input function
default_emr_name=$clustername"-emrcluster"
read -p "EMR Cluster Name[$default_emr_name]: " emrclustername
emrclustername=${emrclustername:-$default_emr_name}
echo $emrclustername
echo "emrclustername:"$emrclustername>> record.txt


read -p "EMR namespace: [emr-on-eks]: " emr_namespace
emr_namespace=${emr_namespace:-emr-on-eks}
echo $emr_namespace
echo "emr_namespace:"$emr_namespace>> record.txt

#prepare the job submission
read -p "Spark job submission role[EMR_EC2_DefaultRole]:" rolename
rolename=${rolename:-EMR_EC2_DefaultRole}
echo "Spark submit role:"$rolename
echo "rolename:"$rolename>> record.txt




#AMP Input Function
read -p "AMP alias[my-first-ws]" ws_alias
ws_alias=${ws_alias:-my-first-ws}
echo "Workspace alias:"$ws_alias
echo "ws_alias:"$ws_alias>> record.txt


read -p "Prometheus namespace[promethus]" prometheus_ns
prometheus_ns=${prometheus_ns:-promethus}
echo "Prometheus namespace:"$prometheus_ns
echo "prometheus_ns:"$prometheus_ns>> record.txt

read -p "Prometheus Chart Name[promethus]" prometheus_chart_name
prometheus_chart_name=${prometheus_chart_name:-promethus}
echo "Prometheus Chart Name:"$prometheus_chart_name
echo "prometheus_chart_name:"$prometheus_chart_name>> record.txt

#create eks cluster
launch_eks_cluster

#create EMR cluster
launch_emr_cluster

#create/update the role for the AMP
create_amp_role

#create the actually AMP
create_amp

#install the prometheus on EKS cluster
install_promethus_on_eks
