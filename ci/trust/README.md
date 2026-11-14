# Consumer trust configuration

Before running the registry consumer workflow, provision the demo publisher
explicitly with `python ci/provision_demo.py --keys-dir local-keys/ci-demo`.
Review the printed fingerprints through a trusted channel, commit only the
three public trust JSON files in this directory, and install the corresponding
private PEMs as the repository secrets named by the provisioning command.

The consumer workflow must never generate a publisher or change release trust
to make verification pass. Public test fixtures under `test_cases/keys` are
separate from the private CI demo keys.
