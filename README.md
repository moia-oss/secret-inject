# secret-inject

Deploying AWS cloud infrastructure from your CI/CD pipeline conventionally requires that you provide production credentials to the deployment pipeline permanently.

Effectively, this means that an attacker who has access to your source code repository can gain access to your production environment, as they can modify code and then deploy that same code to production. It may also imply that you need to rotate those credentials frequently and take other precautions to keep your production environment somewhat secure. `secret-inject` takes a different approach: Short term credentials are generated on the developer's machine and injected into individual pipeline executions securely.

This way, source code access is effectively decoupled from AWS-access. This allows you to simplify and liberalize source code access, frees you from rotating credentials provided to the pipeline, and takes away a big security worry.

## How it works conceptually

`secret-inject` uses S3 as an intermediary between the CI system and the developer's workstation. That's necessary because in CI systems you usually can't open ports to the outside world (which would allow you to receive credentials).

`secret-inject` runs in the CI pipeline and polls the S3 bucket for credentials continuously. It also prompts the developer to run the same `secret-inject` program on their workstation with a specific key, which was provided as a command line parameter in the prompt.

`secret-inject` supports pushing this prompt as a Github PR comment, which will in turn notify the developer, for example via Slack. Other methods of notification are on the roadmap.

The developer pastes something into their terminal which looks like this `secret-inject inject 
0EocAjVYytLIJtLUkSy3aJScojBIdO3urUg0O1G6ZH3k`. The second argument serves as both the basis of the S3 key used for exchanging the credentials and as a public cryptographic key (see section "Security considerations").

On the developer's workstation, `secret-inject` will assume a set of AWS roles and push the generated short-term credentials to the S3 bucket. Every role assumption is associated with one stage of the deployment, for example this could be `dev`, `int`, and `prd`.

`secret-inject`, running on the developer's workstation, will upload the credentials to S3. `secret-inject`, running in the CI workflow, will find the credentials and persist them on the container file system.

In the CI workflow the developer may now conveniently use the credentials like so: `secret-inject execute dev -- your-deploy-script.sh` - where `dev` identifies the stage. If you know the tool [AWS Vault](https://github.com/99designs/aws-vault) you will be familiar with this approach. `secret-inject` opens a subshell in which the credentials for the appropriate environment are available as exported environment variables. 

This means you can deploy to all stages from the same CI-container-instance, cutting down on deployment times.

By default `secret-inject` will enforce the order of stages. This is to protect you from e.g. accidentally deploying to `prd` before deploying to`int`.

If you require separate container instances per stage, then you can also pass the credentials through to other container-instances. `secret-inject` will persist credentials in the file `./secret-inject-cred-set.yaml` by default. CI/CD systems usually allow you to persist local data and pass it on. For example in GitHub Actions this is called "[workflow artifacts](https://docs.github.com/en/actions/guides/storing-workflow-data-as-artifacts)".

## Security considerations

When running in the pipeline, `secret-inject` will first generate a private-public [NaCL Box key-pair](https://nacl.cr.yp.to/box.html) from secure random data. The private key is never published or logged and remains in the RAM of the CI container instance only. The public key is encoded as a command line argument and printed. It can then be used by the `secret-inject` instance running on the developer's workstation.

Before actually sending the credentials, `secret-inject`, running on the developer's workstation, uses the public cryptographic key to securely encrypt the set of credentials. This means that an attacker who gains access to the S3 bucket will only find ciphertext. Even the public key will not be present on the S3 bucket (as the S3 key is a hash of the public key rather than the key itself). Therefore, an attacker can't tamper with the data exchange at all as long as they only have access to the S3 bucket itself.

This means that you need to be somewhat less rigorous about protecting the S3 bucket used for exchange of credentials. You should still use authentication and set up billing alerts to make sure that nobody uses the S3 bucket for illegitimate data exchange such as distribution of malware.

Once the credentials have been received, they will be persisted to the container file system in the CI workflow. An attacker who has compromised the CI system itself could thus access the credentials. Note, however, that credentials will be short-lived (by default they will have a lifetime of 20 minutes).

## Setup

### S3 bucket and IAM user

You need some S3 bucket, it can be an existing one, it can also be a new one. It would make sense to add [lifecycle rules](https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html) such that old credentials are not kept indefinitely. However, since credentials are both encrypted and short-lived, storing them indefinitely does not cause security issues.

For your convenience here's a sample of a CloudFormation template deploying an S3 bucket. You may, however, use any method of deploying the bucket you want, including setting it up in the AWS console. The template also includes an IAM Policy allowing the principal (i.e. user or role) assigned the policy to put and get data to and from the bucket. Once again, you can handle this in different ways if you need to. 

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Creates S3 Bucket and policy

Resources:
  CredentialExchangeBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-credentials-exchange"
      AccessControl: Private
      LifecycleConfiguration:
        Rules:
          - Id: DeleteContentAfter2Days
            Status: 'Enabled'
            ExpirationInDays: 2
  CredentialsExchangePolicy:  
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: "${AWS::StackName}-allow-credentials-exchange"
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: 
              - 's3:GetObject'
              - 's3:PutObject'
            Resource: !Join
              - ''
              - - 'arn:aws:s3:::'
                - !Ref CredentialExchangeBucket
                - /*

```

You will also need an IAM user which is allowed to access this bucket. Creating the user may be most straightforward via AWS console, however, it's completely up to you. The user needs to have read access and write access to the S3 bucket, e.g. you could assign the policy contained the S3 bucket above. 

### Configuration

`secret-inject` is based around the assumption that its config file is placed in the source code repo. This way, the same configuration is available to both instances of the software, i.e. the one running on the developer's workstation and the one running in the CI workflow.

A fully commented sample configuration file is provided [here](examples/secret-inject.yaml). All optional fields are commented out but explained and set to their default value.

By default, `secret-inject` expects the config file to be placed in the root of your repository and called `secret-inject.yaml`. You could choose a different path by using the `--config` flag on the command line invocation.

### Installation on developer workstation and in the CI/CD system 

The tool is a static binary (the program is written in Go) and can be distributed easily.

To install the tool on your workstation just download the [latest release](https://github.com/moia-oss/secret-inject/releases) for your system. Put the binary in a folder which is part of your path, e.g. `/usr/bin/local`.

In the pipeline the recommended way is to use the following two-liner in your deploy script (assuming that you use Linux in the CI system).

```
curl --silent --location --output ./secret-inject $(curl --silent $(curl --silent https://api.github.com/repos/moia-oss/secret-inject/releases/latest | jq -r '.assets_url') | jq -r '.[] | select (.name | contains("linux")) | .browser_download_url')
chmod u+x ./secret-inject
```

This downloads the latest version of the tool to the current directory. Just execute it from the local path, i.e. using `./secret-inject ...`. 

`secret-inject` is agnostic towards the specific CI system being used (though it includes some convenience functions for GitHub actions).

### Awaiting and injecting the credentials

In the CI workflow the await command might simply look like this:

```
./secret-inject await
```

This will prompt the developer to inject the credentials (and optionally cause a GitHub notification).

On the developer workstation: Just paste the command prompted into the command line (using appropriate AWS credentials, e.g. you may want to prefix the command with `aws-vault...`). If you use Git, you may do this from anywhere in the repo, the repo-root will be identified, and the configuration file will be read from there. 

Here's an example of how it might look in practice:

```
aws-vault exec your-root-profile -- secret-inject inject 0EocAjVYytLIJtLUkSy3aJScojBIdO3urUg0O1G6ZH3k
```
