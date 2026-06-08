terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "scanboy-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "scanboy-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ScanBoy"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

module "vpc" {
  source = "./modules/vpc"

  environment    = var.environment
  vpc_cidr       = var.vpc_cidr
  azs            = var.availability_zones
  public_subnets = var.public_subnet_cidrs
  private_subnets = var.private_subnet_cidrs
  sandbox_subnets = var.sandbox_subnet_cidrs
}

module "eks" {
  source = "./modules/eks"

  environment       = var.environment
  cluster_name      = "scanboy-${var.environment}"
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_instance_types = var.eks_node_instance_types
  node_min_size      = var.eks_node_min_size
  node_max_size      = var.eks_node_max_size
  node_desired_size  = var.eks_node_desired_size
}

module "rds" {
  source = "./modules/rds"

  environment       = var.environment
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  instance_class    = var.rds_instance_class
  allocated_storage = var.rds_allocated_storage
  db_name           = "scanboy"
  db_username       = "scanboy"
}

module "elasticache" {
  source = "./modules/elasticache"

  environment    = var.environment
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.private_subnet_ids
  node_type      = var.redis_node_type
  num_cache_nodes = var.redis_num_nodes
}

module "s3" {
  source = "./modules/s3"

  environment = var.environment
  bucket_name = "scanboy-artifacts-${var.environment}"
}

module "elasticsearch" {
  source = "./modules/elasticsearch"

  environment    = var.environment
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = [module.vpc.private_subnet_ids[0]]
  instance_type  = var.es_instance_type
  volume_size    = var.es_volume_size
}
