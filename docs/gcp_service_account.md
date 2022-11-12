# GCP service accounts

I'd recommend not even trying to use the UI, which is awful. Instead, do things via CLI.

# Service account for building and deploying to Google Cloud Run

Export name and project (project must exist already):

    $ export SA_NAME="google-cloud-run-deploy-v4"
    $ export PROJECT="neospring"

Create a service account:

    $ gcloud iam service-accounts create $SA_NAME --display-name=$SA_NAME --project $PROJECT --description="Used to deploy Google Cloud Run from passages-signup's GitHub Actions runs."

Add necessary roles to the service account:

    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/cloudbuild.builds.builder"
    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/run.developer"
    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/run.serviceAgent"
    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/viewer"

Create a service account JSON containing a secret:

    $ gcloud iam service-accounts keys create service-account-key-deploy.json --iam-account=$SA_NAME@$PROJECT.iam.gserviceaccount.com

Use the contents of `service-account-key-deploy.json` to put in the `GCP_CREDENTIALS_JSON` GitHub Actions secret for the build to work.

# Service account for using storage service

Export name and project (project must exist already):

    $ export SA_NAME="google-cloud-storage"
    $ export PROJECT="neospring"

Create a service account:

    $ gcloud iam service-accounts create $SA_NAME --display-name=$SA_NAME --project $PROJECT --description="Used to create and get Spring '83 boards through GCP's storage service."

Add necessary roles to the service account:

    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/storage.objectCreator"
    $ gcloud projects add-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/storage.objectViewer"

Create a service account JSON containing a secret:

    $ gcloud iam service-accounts keys create service-account-key-storage.json --iam-account=$SA_NAME@$PROJECT.iam.gserviceaccount.com

Use the contents of `service-account-key-storage.json` to put in the `GCP_CREDENTIALS_JSON` Google Cloud Run env var to use GCP storage as a backend.

## Debugging

Dump a list of all roles to file:

    $ gcloud iam roles list > all_roles

Same thing, but just the role names for quick reference:

    $ gcloud iam roles list | grep 'name: ' > all_roles

Removing a role from a service account:

    $ gcloud projects remove-iam-policy-binding neospring --member="serviceAccount:$SA_NAME@$PROJECT.iam.gserviceaccount.com" --role="roles/cloudbuild.serviceAgent"

This error which is straight from hell is a problem wherein the CLI fails because it can't stream build output. Being inscrutable error messages and permissions caching that makes being sure of anything very difficult, _I believe_ the resolution was to add `roles/viewer`, but it's really hard to tell:

    ERROR: (gcloud.builds.submit) 
    The build is running, and logs are being written to the default logs bucket.
    This tool can only stream logs if you are Viewer/Owner of the project and, if applicable, allowed by your VPC-SC security policy.

A list of roles that I tried, but which didn't seem to be needed in the end with the matrix above:

* `roles/cloudbuild.builds.editor`
* `roles/cloudbuild.builds.viewer`
* `roles/cloudbuild.serviceAgent`
* `roles/iam.serviceAccountUser`
* `roles/serviceusage.serviceUsageConsumer`
* `run.admin`
