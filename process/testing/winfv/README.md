FV framework for windows on aws. 


From Jenkins job
- Jenkins jobs check out source repo and build windows binaries. 
- Jenkins jobs check out process repo.
- Jenkins jobs copy over run-fv.ps1 from source repo for setup-fv.sh.
- Jenkins jobs setup parameters, copy over keys and docker credentials for setup-fv.sh.
- Call setup-fv.sh script.

From setup-fv.sh
- Setup VPC resources.
- Create and bootstrap linux node (install docker) and windows node (setup etcd-endpoints, install pscp.exe and putty key to transfer files between windows and linux nodes).
- Copy over run-fv.ps1 to linux node, add a line to copy back report from windows node to linux node.
- Copy over docker credentials and log in to grc.io. Start etcd, kube-apiserver, kube-controller-manager on linux nodes.
- Setup wait-report.sh on linux node. 
- Windows node wait until it found a file named `file-ready` on linux node.

From Jenkins Jobs
- Copy over windows binaries and run-fv.ps1 script to linux node.
- Touch a file `file-ready` which tells windows nodes to copy over windows binaries and run-fv.ps1.
- Call linux wait-report.sh to wait for report.xml file.

From setup-fv.sh
- Windows detected the presence of file-ready on linux node and copy over binaries and run-fv.ps1.
- Windows node start to run run-fv.ps1.
- The last line of run-fv.ps1 will copy over report.xml to linux node.

From Jenkins Jobs
- Wait-report.sh exit once report.xml is present on linux node.
- Copy back report.xml from linux to wavetank slave.
- Check report.xml for test result.
