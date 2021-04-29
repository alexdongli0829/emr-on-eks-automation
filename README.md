# emr-on-eks-automation
automatically create EKS, EMR and Aamzon Managed Prometheus


# prerequesite

## package needed: kubectl, eksctl, helm, awscli v2, jq

Install on AL2:

```
#kubectl
curl -s -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl

chmod +x ./kubectl

mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin


#eksctl

curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp

sudo mv /tmp/eksctl /usr/local/bin



#aws cli version 2
sudo yum remove -y awscli

curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

sudo ./aws/install --bin-dir /usr/local/bin


#helm
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
bash get_helm.sh

#jq

sudo yum install -y jq
```

## Need miminum IAM permission

### Permission needed to create EKS cluster:
https://eksctl.io/usage/minimum-iam-policies/

### Permission needed to create EMR on EKS:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "emrcontainer",
            "Effect": "Allow",
            "Action": [
                "emr-containers:DescribeVirtualCluster",
                "emr-containers:ListVirtualClusters",
                "emr-containers:CreateVirtualCluster"
            ],
            "Resource": "*"
        },
        {
            "Sid": "iampermission",
            "Effect": "Allow",
            "Action": "iam:ListRoles",
            "Resource": "*"
        }
    ]
}
```

### Permission for AMP:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "iam",
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicy",
                "iam:GetRole",
                "iam:UpdateAssumeRolePolicy",
                "iam:CreateRole",
                "iam:AttachRolePolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "sts",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*"
        },
        {
            "Sid": "eks",
            "Effect": "Allow",
            "Action": "eks:DescribeCluster",
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "aps:CreateWorkspace",
                "aps:DescribeWorkspace"
            ],
            "Resource": "*"
        }
    ]
}
```

