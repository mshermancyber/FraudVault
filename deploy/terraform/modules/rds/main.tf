variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "instance_class" { type = string }
variable "allocated_storage" { type = number }
variable "db_name" { type = string }
variable "db_username" { type = string }

resource "aws_db_subnet_group" "main" {
  name       = "scanboy-${var.environment}"
  subnet_ids = var.subnet_ids
  tags       = { Name = "scanboy-${var.environment}-db-subnet" }
}

resource "aws_security_group" "rds" {
  name_prefix = "scanboy-${var.environment}-rds-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "scanboy-${var.environment}-rds-sg" }
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db" {
  name = "scanboy/${var.environment}/database"
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db.result
    host     = aws_db_instance.main.address
    port     = 5432
    dbname   = var.db_name
    url      = "postgresql://${var.db_username}:${random_password.db.result}@${aws_db_instance.main.address}:5432/${var.db_name}"
  })
}

resource "aws_db_instance" "main" {
  identifier     = "scanboy-${var.environment}"
  engine         = "postgres"
  engine_version = "16.3"
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.allocated_storage * 2
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az                = var.environment == "production"
  backup_retention_period = 30
  deletion_protection     = var.environment == "production"
  skip_final_snapshot     = var.environment != "production"

  performance_insights_enabled = true

  tags = { Name = "scanboy-${var.environment}-postgres" }
}

output "endpoint" { value = aws_db_instance.main.address }
output "secret_arn" { value = aws_secretsmanager_secret.db.arn }
