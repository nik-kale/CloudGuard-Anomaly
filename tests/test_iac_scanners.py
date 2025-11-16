"""
Tests for Infrastructure-as-Code scanners.
"""

import tempfile
import os
from pathlib import Path
import pytest

from cloudguard_anomaly.iac.terraform_scanner import TerraformScanner
from cloudguard_anomaly.iac.cloudformation_scanner import CloudFormationScanner
from cloudguard_anomaly.core.models import ResourceType, CloudProvider


class TestTerraformScanner:
    """Test Terraform IaC scanning."""

    def test_scanner_initialization(self):
        """Test Terraform scanner initializes."""
        scanner = TerraformScanner()
        assert scanner is not None

    def test_parse_s3_bucket(self):
        """Test parsing Terraform S3 bucket."""
        tf_content = """
resource "aws_s3_bucket" "example" {
  bucket = "my-test-bucket"

  tags = {
    Environment = "production"
    Owner       = "security-team"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(tf_content)
            temp_path = f.name

        try:
            scanner = TerraformScanner()
            env = scanner.scan_file(temp_path)

            assert env is not None
            assert len(env.resources) >= 1

            # Find S3 bucket
            s3_buckets = [r for r in env.resources if r.type == ResourceType.STORAGE]
            assert len(s3_buckets) >= 1

            bucket = s3_buckets[0]
            assert "my-test-bucket" in bucket.name or "example" in bucket.name
            assert "Environment" in bucket.tags

        finally:
            os.unlink(temp_path)

    def test_parse_ec2_instance(self):
        """Test parsing Terraform EC2 instance."""
        tf_content = """
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  monitoring = true

  tags = {
    Name = "web-server"
  }
}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(tf_content)
            temp_path = f.name

        try:
            scanner = TerraformScanner()
            env = scanner.scan_file(temp_path)

            ec2_instances = [r for r in env.resources if r.type == ResourceType.COMPUTE]
            assert len(ec2_instances) >= 1

            instance = ec2_instances[0]
            assert instance.properties.get("instance_type") == "t2.micro"
            assert instance.properties.get("monitoring_enabled") is True

        finally:
            os.unlink(temp_path)

    def test_parse_security_group(self):
        """Test parsing Terraform security group."""
        tf_content = """
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(tf_content)
            temp_path = f.name

        try:
            scanner = TerraformScanner()
            env = scanner.scan_file(temp_path)

            sg_resources = [r for r in env.resources if r.type == ResourceType.NETWORK]
            assert len(sg_resources) >= 1

            sg = sg_resources[0]
            assert "ingress_rules" in sg.properties or "ingress" in sg.properties

        finally:
            os.unlink(temp_path)

    def test_scan_directory(self):
        """Test scanning directory of Terraform files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple .tf files
            Path(tmpdir, "main.tf").write_text("""
resource "aws_s3_bucket" "bucket1" {
  bucket = "bucket-1"
}
""")

            Path(tmpdir, "ec2.tf").write_text("""
resource "aws_instance" "instance1" {
  ami           = "ami-123"
  instance_type = "t2.micro"
}
""")

            scanner = TerraformScanner()
            env = scanner.scan_directory(tmpdir)

            # Should find resources from both files
            assert len(env.resources) >= 2

    def test_invalid_terraform_file(self):
        """Test handling of invalid Terraform syntax."""
        tf_content = "this is not valid HCL"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(tf_content)
            temp_path = f.name

        try:
            scanner = TerraformScanner()
            # Should handle gracefully
            env = scanner.scan_file(temp_path)
            # May return empty environment or raise exception
            assert env is not None

        finally:
            os.unlink(temp_path)


class TestCloudFormationScanner:
    """Test CloudFormation IaC scanning."""

    def test_scanner_initialization(self):
        """Test CloudFormation scanner initializes."""
        scanner = CloudFormationScanner()
        assert scanner is not None

    def test_parse_s3_bucket_yaml(self):
        """Test parsing CloudFormation S3 bucket (YAML)."""
        cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Test S3 bucket

Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      Tags:
        - Key: Environment
          Value: production
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            assert env is not None
            assert len(env.resources) >= 1

            s3_buckets = [r for r in env.resources if r.type == ResourceType.STORAGE]
            assert len(s3_buckets) >= 1

            bucket = s3_buckets[0]
            assert "Environment" in bucket.tags or len(bucket.tags) > 0

        finally:
            os.unlink(temp_path)

    def test_parse_s3_bucket_json(self):
        """Test parsing CloudFormation S3 bucket (JSON)."""
        cfn_content = """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "my-json-bucket",
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": true,
          "BlockPublicPolicy": true
        }
      }
    }
  }
}"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            s3_buckets = [r for r in env.resources if r.type == ResourceType.STORAGE]
            assert len(s3_buckets) >= 1

        finally:
            os.unlink(temp_path)

    def test_parse_ec2_instance(self):
        """Test parsing CloudFormation EC2 instance."""
        cfn_content = """
Resources:
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c55b159cbfafe1f0
      InstanceType: t2.micro
      Monitoring: true
      SecurityGroupIds:
        - sg-12345
      Tags:
        - Key: Name
          Value: web-server
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            ec2_instances = [r for r in env.resources if r.type == ResourceType.COMPUTE]
            assert len(ec2_instances) >= 1

            instance = ec2_instances[0]
            assert instance.properties.get("instance_type") == "t2.micro"

        finally:
            os.unlink(temp_path)

    def test_parse_security_group(self):
        """Test parsing CloudFormation security group."""
        cfn_content = """
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            sg_resources = [r for r in env.resources if r.type == ResourceType.NETWORK]
            assert len(sg_resources) >= 1

        finally:
            os.unlink(temp_path)

    def test_parse_iam_role(self):
        """Test parsing CloudFormation IAM role."""
        cfn_content = """
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: test-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            iam_resources = [r for r in env.resources if r.type == ResourceType.IDENTITY]
            assert len(iam_resources) >= 1

        finally:
            os.unlink(temp_path)

    def test_invalid_cloudformation_template(self):
        """Test handling of invalid CloudFormation template."""
        cfn_content = "invalid: [yaml: content:"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            # Should handle gracefully
            env = scanner.scan_template(temp_path)
            assert env is not None

        finally:
            os.unlink(temp_path)

    def test_multiple_resources_in_template(self):
        """Test template with multiple resources."""
        cfn_content = """
Resources:
  Bucket1:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: bucket-1

  Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: bucket-2

  Instance1:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-123
      InstanceType: t2.micro
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            # Should find 3 resources
            assert len(env.resources) >= 3

        finally:
            os.unlink(temp_path)


class TestIaCIntegration:
    """Test IaC scanner integration with analysis engine."""

    def test_scan_terraform_and_analyze(self):
        """Test scanning Terraform and running security analysis."""
        from cloudguard_anomaly.core.engine import AnalysisEngine

        tf_content = """
resource "aws_s3_bucket" "insecure" {
  bucket = "insecure-bucket"
}

resource "aws_security_group" "open_ssh" {
  name = "open-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(tf_content)
            temp_path = f.name

        try:
            # Scan Terraform
            scanner = TerraformScanner()
            env = scanner.scan_file(temp_path)

            # Run security analysis
            engine = AnalysisEngine(enable_agents=False, enable_drift_detection=False)
            result = engine.scan_environment(env)

            # Should find security issues
            assert result.findings is not None
            assert len(result.findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_cloudformation_and_analyze(self):
        """Test scanning CloudFormation and running security analysis."""
        from cloudguard_anomaly.core.engine import AnalysisEngine

        cfn_content = """
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: public-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(cfn_content)
            temp_path = f.name

        try:
            # Scan CloudFormation
            scanner = CloudFormationScanner()
            env = scanner.scan_template(temp_path)

            # Run security analysis
            engine = AnalysisEngine(enable_agents=False, enable_drift_detection=False)
            result = engine.scan_environment(env)

            # Should find security issues
            assert result.findings is not None

        finally:
            os.unlink(temp_path)
