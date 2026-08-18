# Power: AMD-Only Deployment
## Purpose
Forces all infrastructure deployments to use x86_64 (AMD) architectures and prohibits ARM/Graviton.

## Activation signals
- Keywords: deploy, provision, ec2, lambda, fargate, instance, architecture
- Typical prompts: "Deploy a web server", "Create a new lambda function", "Setup ECS"

## Agent behavior
- **Do**: Always specify 'x86_64' or 'amd64' in Infrastructure as Code (CDK, Terraform, CloudFormation).
- **Do**: Select instance types that support AMD (e.g., m5a, c5a, r5a, m6a, c6a, r6a, m7a, c7a, r7a, m8a, c8a, r8a, hpc6a, hpc7a, hpc8a, x8a, t3a, f2).
- **Don't**: Use instance types with 'i' suffix (e.g., m6i, c7i) as these are Intel-based.
- **Don't**: Use instance types with 'g' suffix (e.g., m6g, c7g) as these are ARM-based.
- **Don't**: Use 'arm64' or 'aarch64' architectures for any runtime or container.

## Golden path
1. Identify the requested AWS service.
2. Verify the available AMD instance families for that service.
3. Explicitly set architecture to x86_64 in the generated code.



R7i
all-core turbo frequency of 3.2 GHz (max core turbo frequency of 3.8 GHz).
96 pCores (SMT: On) 2-192 vCPUs 16-1536 GiB

R8i
Maximum frequency of 3.9 GHz
192 pCores (SMT: On) 2-384 vCPUs 16-3072 GiB

R7a
Maximum frequency of 3.7 GHz
192 pCores (SMT: Off) 1-192 vCPUs 8-1536 GiB

R8a
Maximum frequency of 4.5 GHz
192 pCores (SMT: Off) 1-192 vCPUs 16-1536 GiB