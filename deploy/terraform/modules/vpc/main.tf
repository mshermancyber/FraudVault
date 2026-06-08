variable "environment" { type = string }
variable "vpc_cidr" { type = string }
variable "azs" { type = list(string) }
variable "public_subnets" { type = list(string) }
variable "private_subnets" { type = list(string) }
variable "sandbox_subnets" { type = list(string) }

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "scanboy-${var.environment}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "scanboy-${var.environment}-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                     = "scanboy-${var.environment}-public-${count.index}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name                              = "scanboy-${var.environment}-private-${count.index}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "sandbox" {
  count             = length(var.sandbox_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.sandbox_subnets[count.index]
  availability_zone = var.azs[count.index % length(var.azs)]

  tags = { Name = "scanboy-${var.environment}-sandbox-${count.index}" }
}

resource "aws_eip" "nat" {
  count  = length(var.public_subnets)
  domain = "vpc"
  tags   = { Name = "scanboy-${var.environment}-nat-${count.index}" }
}

resource "aws_nat_gateway" "main" {
  count         = length(var.public_subnets)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "scanboy-${var.environment}-nat-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "scanboy-${var.environment}-public" }
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = length(var.private_subnets)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  tags = { Name = "scanboy-${var.environment}-private-${count.index}" }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table" "sandbox" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "scanboy-${var.environment}-sandbox-isolated" }
}

resource "aws_route_table_association" "sandbox" {
  count          = length(var.sandbox_subnets)
  subnet_id      = aws_subnet.sandbox[count.index].id
  route_table_id = aws_route_table.sandbox.id
}

resource "aws_network_acl" "sandbox" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.sandbox[*].id

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "deny"
    cidr_block = "10.0.0.0/8"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "deny"
    cidr_block = "172.16.0.0/12"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 300
    action     = "deny"
    cidr_block = "192.168.0.0/16"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 400
    action     = "deny"
    cidr_block = "169.254.0.0/16"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 900
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "scanboy-${var.environment}-sandbox-nacl" }
}

output "vpc_id" { value = aws_vpc.main.id }
output "public_subnet_ids" { value = aws_subnet.public[*].id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "sandbox_subnet_ids" { value = aws_subnet.sandbox[*].id }
