import os
from datetime import datetime
import sh
import tarfile
import socket
import tempfile
import subprocess
from datastore import DatastoreClient
from etcd import EtcdException
from shutil import copytree

def save_diags(upload=False):
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    temp_diags_dir = os.path.join(temp_dir, 'diagnostics')
    os.mkdir(temp_diags_dir)
    print("Using temp dir: %s" % temp_dir)

    # Write date to file
    with open(os.path.join(temp_diags_dir, 'date'), 'w') as f:
        f.write("DATE=%s" % datetime.strftime(datetime.today(),"%Y-%m-%d_%H-%M-%S"))

    # Write hostname to file
    with open(os.path.join(temp_diags_dir, 'hostname'), 'w') as f:
        f.write("%s" % socket.gethostname())

    # Write netstat output to file
    with open(os.path.join(temp_diags_dir, 'netstat'), 'w') as f:
        try:
            print("Dumping netstat output")
            netstat = sh.Command._create("netstat")
            f.writelines(netstat("-an"))
        except sh.CommandNotFound as e:
            print "Missing command: %s" % e.message

    # Write routes
    print("Dumping routes")
    with open(os.path.join(temp_diags_dir, 'route'), 'w') as f:
        try:
            route = sh.Command._create("route")
            f.write("route -n")
            f.writelines(route("-n"))
            f.write('\n')
        except sh.CommandNotFound as e:
            print "Missing command: %s" % e.message

        try:
            ip = sh.Command._create("ip")
            f.write("ip route")
            f.writelines(ip("route"))
            f.write('\n')

            f.write("ip -6 route")
            f.writelines(ip("-6", "route"))
            f.write('\n')
        except sh.CommandNotFound as e:
            print "Missing command: %s" % e.message

    # Dump iptables
    with open(os.path.join(temp_diags_dir, 'iptables'), 'w') as f:
        try:
            iptables_save = sh.Command._create("iptables-save")
            print("Dumping iptables")
            f.writelines(iptables_save())
        except sh.CommandNotFound as e:
            print "Missing command: %s" % e.message

    # Dump ipset list
    # TODO: ipset might not be installed on the host. But we don't want to
    # gather the diags in the container because it might not be running...
    with open(os.path.join(temp_diags_dir, 'ipset'), 'w') as f:
        try:
            ipset = sh.Command._create("ipset")
            print("Dumping ipset")
            f.writelines(ipset("list"))
        except sh.CommandNotFound as e:
            print "Missing command: %s" % e.message

    print("Copying Calico logs")
    calico_dir = '/var/log/calico'
    copytree(calico_dir, os.path.join(temp_diags_dir, "logs"))

    print("Dumping datastore")
    # TODO: May want to move this into datastore.py as a dump-calico function
    try:
        datastore_client = DatastoreClient()
        datastore_data = datastore_client.etcd_client.read("/calico/v2/keys/calico", recursive=True)
        with open(os.path.join(temp_diags_dir, 'etcd_calico')) as f:
            f.writelines(datastore_data)
    except EtcdException:
        print "Unable to dump etcd datastore"

    # Create tar and upload
    tar_filename = datetime.strftime(datetime.today(),"diags-%d%m%y_%H%M%S.tar.gz")
    full_tar_path = os.path.join(temp_dir, tar_filename)
    with tarfile.open(full_tar_path, "w:gz") as tar:
        # pass in arcname, otherwise zip contains layers of subfolders
        tar.add(temp_dir, arcname="")

    print("Diags saved to %s" % (full_tar_path))

    if upload:
        upload_temp_diags(full_tar_path)


def upload_temp_diags(diags_path):
    # TODO: Rewrite into httplib
    print("Uploading file. Available for 14 days from the URL printed when the upload completes")
    curl_cmd = ["curl", "--upload-file", diags_path, os.path.join("https://transfer.sh", os.path.basename(diags_path))]
    curl_process = subprocess.Popen(curl_cmd)
    curl_process.communicate()
    curl_process.wait()
    print("Done")

