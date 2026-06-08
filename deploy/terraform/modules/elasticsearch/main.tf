variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "instance_type" { type = string }
variable "volume_size" { type = number }

resource "aws_security_group" "es" {
  name_prefix = "scanboy-${var.environment}-es-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "scanboy-${var.environment}-es-sg" }
}

resource "aws_opensearch_domain" "main" {
  domain_name    = "scanboy-${var.environment}"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type  = var.instance_type
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.es.id]
  }

  encrypt_at_rest { enabled = true }
  node_to_node_encryption { enabled = true }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  tags = { Name = "scanboy-${var.environment}-opensearch" }
}

output "endpoint" { value = aws_opensearch_domain.main.endpoint }
output "domain_arn" { value = aws_opensearch_domain.main.arn }
