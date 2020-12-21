terraform {
  required_providers {
    tls = {
      source = "hashicorp/tls"
      version = "3.0.0"
    }
    local = {
      source = "hashicorp/local"
      version = "2.0.0"
    }    
    template = {
      source = "hashicorp/template"
      version = "2.2.0"
    }
    external = {
      source = "hashicorp/external"
      version = "2.0.0"
    }
  }
}
provider "tls" {
  # Configuration options
}

provider "local" {
  version = "2.0.0"
}

provider "template" {
  version = "2.2.0"
}

provider "external" {
  version = "2.0.0"
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  version                = "~> 1.10"
}

data "aws_eks_cluster" "cluster" {
  name = aws_eks_cluster.main.id
}

data "aws_eks_cluster_auth" "cluster" {
  name = aws_eks_cluster.main.id
}

resource "aws_iam_policy" "AmazonEKSClusterCloudWatchMetricsPolicy" {
  name   = "AmazonEKSClusterCloudWatchMetricsPolicy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "cloudwatch:PutMetricData"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "AmazonEKSClusterNLBPolicy" {
  name   = "AmazonEKSClusterNLBPolicy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "elasticloadbalancing:*",
                "ec2:CreateSecurityGroup",
                "ec2:Describe*"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
EOF
}

resource "aws_iam_role" "eks_cluster_role" {
  name                  = "${var.name}-eks-cluster-role"
  force_detach_policies = true

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "eks.amazonaws.com",
          "eks-fargate-pods.amazonaws.com"
          ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# # ------------------- Cloud watch Commented out -------------------------
# resource "aws_iam_role_policy_attachment" "AmazonEKSCloudWatchMetricsPolicy" {
#   policy_arn = aws_iam_policy.AmazonEKSClusterCloudWatchMetricsPolicy.arn
#   role       = aws_iam_role.eks_cluster_role.name
# }

resource "aws_iam_role_policy_attachment" "AmazonEKSCluserNLBPolicy" {
  policy_arn = aws_iam_policy.AmazonEKSClusterNLBPolicy.arn
  role       = aws_iam_role.eks_cluster_role.name
}

# # ------------------- Cloud watch Commented out -------------------------
# resource "aws_cloudwatch_log_group" "eks_cluster" {
#   name              = "/aws/eks/${var.name}-${var.environment}/cluster"
#   retention_in_days = 30

#   tags = {
#     Name        = "${var.name}-${var.environment}-eks-cloudwatch-log-group"
#     Environment = var.environment
#   }
# }

resource "aws_eks_cluster" "main" {
  name     = "${var.name}-${var.environment}"
  role_arn = aws_iam_role.eks_cluster_role.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids = concat(var.public_subnets.*.id, var.private_subnets.*.id)
  }

  timeouts {
    delete = "30m"
  }

  depends_on = [
#    aws_cloudwatch_log_group.eks_cluster,
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSServicePolicy
  ]
}

# # Fetch OIDC provider thumbprint for root CA
# data "external" "thumbprint" {
#   program =    ["${path.module}/oidc_thumbprint.sh", var.region]
#   depends_on = [aws_eks_cluster.main]
# }

# resource "aws_iam_openid_connect_provider" "main" {
#   client_id_list  = ["sts.amazonaws.com"]
#   thumbprint_list = [data.external.thumbprint.result.thumbprint]
#   url             = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer

#   lifecycle {
#     ignore_changes = [thumbprint_list]
#   }
# }

# Fetch OIDC provider thumbprint for root CA
# deployment of OPEN ID connector to replace the 

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.main.identity.0.oidc.0.issuer
}
resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list = ["sts.amazonaws.com"]
#  thumbprint_list = concat([data.tls_certificate.cluster.certificates.0.sha1_fingerprint], var.oidc_thumbprint_list)
  thumbprint_list = [data.tls_certificate.cluster.certificates.0.sha1_fingerprint]
  url = aws_eks_cluster.main.identity.0.oidc.0.issuer
}

# ------------------ Node Group Beginning ------------------
# Commented out Node Group as we are using only Fargate

# resource "aws_iam_role" "eks_node_group_role" {
#   name                  = "${var.name}-eks-node-group-role"
#   force_detach_policies = true

#   assume_role_policy = <<POLICY
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Principal": {
#         "Service": [
#           "ec2.amazonaws.com"
#           ]
#       },
#       "Action": "sts:AssumeRole"
#     }
#   ]
# }
# POLICY
# }

# resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
#   role       = aws_iam_role.eks_node_group_role.name
# }

# resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
#   role       = aws_iam_role.eks_node_group_role.name
# }

# resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
#   role       = aws_iam_role.eks_node_group_role.name
# }

# resource "aws_eks_node_group" "main" {
#   cluster_name    = aws_eks_cluster.main.name
#   node_group_name = "kube-system"
#   node_role_arn   = aws_iam_role.eks_node_group_role.arn
#   subnet_ids      = var.private_subnets.*.id

#   scaling_config {
#     desired_size = 2
#     max_size     = 4
#     min_size     = 2
#   }

#   instance_types  = ["t2.micro"]

#   version = var.k8s_version

#   tags = {
#     Name        = "${var.name}-${var.environment}-eks-node-group"
#     Environment = var.environment
#   }

#   # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
#   # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
#   depends_on = [
#     aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
#     aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
#     aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
#   ]
# }

# ------------------ Node Group Ending ------------------

data "template_file" "kubeconfig" {
  template = <<EOF
apiVersion: v1
kind: Config
current-context: ${data.aws_eks_cluster.cluster.id}
clusters:
- name: ${data.aws_eks_cluster.cluster.id}
  cluster:
    certificate-authority-data: ${data.aws_eks_cluster.cluster.certificate_authority.0.data}
    server: ${data.aws_eks_cluster.cluster.endpoint}
contexts:
- name: ${data.aws_eks_cluster.cluster.id}
  context:
    cluster: ${data.aws_eks_cluster.cluster.id}
    user: ${data.aws_eks_cluster.cluster.id}
users:
- name: ${data.aws_eks_cluster.cluster.id}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      args:
      - --region
      - us-east-1
      - eks
      - get-token
      - --cluster-name
      - ${data.aws_eks_cluster.cluster.id}
      command: aws
EOF

  vars = {
    kubeconfig_name           = "eks_${aws_eks_cluster.main.name}"
    clustername               = aws_eks_cluster.main.name
    endpoint                  = data.aws_eks_cluster.cluster.endpoint
    cluster_auth_base64       = data.aws_eks_cluster.cluster.certificate_authority[0].data
  }


}

# data "template_file" "kubeconfig" {
#   template = file("${path.module}/templates/kubeconfig.tpl")

#   vars = {
#     kubeconfig_name           = "eks_${aws_eks_cluster.main.name}"
#     clustername               = aws_eks_cluster.main.name
#     endpoint                  = data.aws_eks_cluster.cluster.endpoint
#     cluster_auth_base64       = data.aws_eks_cluster.cluster.certificate_authority[0].data
#   }
# }

resource "local_file" "kubeconfig" {
  content  = data.template_file.kubeconfig.rendered
  filename = pathexpand("${var.kubeconfig_path}/config")
}

# resource "null_resource" "coredns_patch" {
#   provisioner "local-exec" {
#     interpreter = ["/bin/bash", "-c"]
#     command     = <<EOF
# kubectl --kubeconfig=<(echo '${data.template_file.kubeconfig.rendered}') patch deployment coredns --namespace kube-system --type=json -p='[{"op": "replace", "path": "/spec/template/metadata/annotations/eks.amazonaws.com~1compute-type", "value": "fargate"}]'
# EOF
#   }
# }

# Patching CoreDNS annotations by deleteing the AWS Compute Type totally 
resource "null_resource" "coredns_patch" {
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<EOF
kubectl --kubeconfig=<(echo '${data.template_file.kubeconfig.rendered}') patch deployment coredns --namespace kube-system --type=json -p='[{"op": "remove", "path": "/spec/template/metadata/annotations", "value": "eks.amazonaws.com/compute-type"}]'
EOF
  }
}

output "kubectl_config" {
  description = "Path to new kubectl config file"
  value       = pathexpand("${var.kubeconfig_path}/config")
}

output "cluster_id" {
  description = "ID of the created cluster"
  value       = aws_eks_cluster.main.id
}
