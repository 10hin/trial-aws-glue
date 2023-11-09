terraform {
  required_version = "1.6.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "ap-northeast-1"
  default_tags {
    tags = {
      Purpose = "CrawlVPCAurora"
    }
  }
}

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "crawl-vpc-aurora"
  cidr = "10.0.0.0/16"
  azs = [
    "ap-northeast-1c",
    "ap-northeast-1d",
  ]
  private_subnets = [
    "10.0.0.0/24",
    "10.0.1.0/24",
  ]
  database_subnets = [
    "10.0.64.0/24",
    "10.0.65.0/24",
  ]
  public_subnets = [
    "10.0.128.0/24",
    "10.0.129.0/24",
  ]
  enable_nat_gateway           = false
  single_nat_gateway           = false
  one_nat_gateway_per_az       = false
  create_database_subnet_group = true
}

data "aws_ami" "al2023" {
  most_recent = true
  owners = [
    "137112412989",
  ]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
module "bastion" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.5.0"

  name          = "crawl-vpc-aurora-bastion"
  instance_type = "t3.nano"
  key_name      = "private-key"
  vpc_security_group_ids = [
    aws_security_group.bastion.id,
  ]
  subnet_id            = module.network.private_subnets[0]
  ami                  = data.aws_ami.al2023.image_id
  iam_instance_profile = aws_iam_instance_profile.bastion.name
}
resource "aws_security_group" "bastion" {
  name   = "crawl-vpc-aurora-bastion"
  vpc_id = module.network.vpc_id
}
resource "aws_iam_role" "bastion" {
  name               = "crawl-vpc-aurora-bastion"
  assume_role_policy = data.aws_iam_policy_document.allow_assume_by_bastion.json
}
data "aws_iam_policy_document" "allow_assume_by_bastion" {
  statement {
    actions = [
      "sts:AssumeRole",
    ]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "allow_session_manager" {
  name   = "allow_session_manager"
  role   = aws_iam_role.bastion.name
  policy = data.aws_iam_policy_document.allow_session_manager.json
}
data "aws_iam_policy_document" "allow_session_manager" {
  statement {
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "ssm:UpdateInstanceInformation",
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::sessionmanager.129008548655/*"
    ]
  }
  statement {
    actions = [
      "s3:GetEncryptionConfiguration",
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "kms:GenerateDataKey",
    ]
    resources = [
      "*"
    ]
  }
}
resource "aws_iam_instance_profile" "bastion" {
  name = "crawl-vpc-aurora-bastion"
  role = aws_iam_role.bastion.name
}

resource "aws_vpc_endpoint" "asm" {
  vpc_id              = module.network.vpc_id
  service_name        = "com.amazonaws.ap-northeast-1.secretsmanager"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}
resource "aws_security_group" "asm" {
  name   = "asm-endpoint"
  vpc_id = module.network.vpc_id
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = module.network.vpc_id
  service_name        = "com.amazonaws.ap-northeast-1.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}
resource "aws_security_group" "ssm" {
  name   = "ssm-endpoint"
  vpc_id = module.network.vpc_id
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = module.network.vpc_id
  service_name        = "com.amazonaws.ap-northeast-1.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}
resource "aws_security_group" "ec2messages" {
  name   = "ec2messages-endpoint"
  vpc_id = module.network.vpc_id
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = module.network.vpc_id
  service_name        = "com.amazonaws.ap-northeast-1.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}
resource "aws_security_group" "ssmmessages" {
  name   = "ssmmessages-endpoint"
  vpc_id = module.network.vpc_id
}

module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "8.5.0"

  name           = "crawl-vpc-aurora"
  engine         = "aurora-mysql"
  engine_version = "8.0.mysql_aurora.3.05.0"
  instance_class = "db.t4g.medium"
  instances = {
    instance1 = {}
    instance2 = {}
  }

  vpc_id               = module.network.vpc_id
  db_subnet_group_name = module.network.database_subnet_group_name
  master_username      = "admin"

  skip_final_snapshot = true
}

resource "aws_vpc_security_group_ingress_rule" "bastion_to_ssm" {
  security_group_id            = aws_security_group.ssm.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.bastion.id
}
resource "aws_vpc_security_group_egress_rule" "bastion_to_ssm" {
  security_group_id            = aws_security_group.bastion.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.ssm.id
}

resource "aws_vpc_security_group_ingress_rule" "bastion_to_ec2messages" {
  security_group_id            = aws_security_group.ec2messages.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.bastion.id
}
resource "aws_vpc_security_group_egress_rule" "bastion_to_ec2messages" {
  security_group_id            = aws_security_group.bastion.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.ec2messages.id
}

resource "aws_vpc_security_group_ingress_rule" "bastion_to_ssmmessages" {
  security_group_id            = aws_security_group.ssmmessages.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.bastion.id
}
resource "aws_vpc_security_group_egress_rule" "bastion_to_ssmmessages" {
  security_group_id            = aws_security_group.bastion.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.ssmmessages.id
}
