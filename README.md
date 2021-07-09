# php-sts-temp-credentials
Generate temporary session token with https://sts.amazonaws.com

Generate temporary session token, access key id, access secret key with https://sts.amazonaws.com with PHP.

This script assumes you have already setup your AWS account and applied proper permissions to your account to access it. if you have not yet setup your IAM AWS user, follow these steps:
https://github.com/amzn/selling-partner-api-docs/blob/main/guides/en-US/developer-guide/SellingPartnerApiDeveloperGuide.md#step-1-create-an-aws-account

## Where to get your Access Key and Access Secret
- Login to your console.aws.amazon.com account
- Click **Users**
- Click the user you want to access
- Click the **Security credentials** tab
- Located under **Access Keys** will be your existing keys. 
- 
If you did not record your access secret, you will need to generate a new one using the **Create access key** button.

## Locating your RoleArn
- Click **Roles** under your aws account
- Click the admin group you want to access
- Copy the Role ARN at the top of the page.

## Enter your credentials
At the bottom of signaturev4.php, modify the following lines with your credentials
- $accessKey = Your access key you generated in the above step
- $secretKey = Your access secret you generated in the above step
- $roleArn = Enter your Role ARN from your amazon account.

Run the script! Enjoy!
