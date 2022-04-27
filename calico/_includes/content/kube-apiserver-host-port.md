First, make a note of the address of the API server:

   - If you have a single API server with a static IP address, you can use its IP address and port.  The IP can be found by running:

     ```bash
     kubectl get endpoints kubernetes -o wide
     ```

     The output should look like the following, with a single IP address and port under "ENDPOINTS":

     ```
     NAME         ENDPOINTS             AGE
     kubernetes   172.16.101.157:6443   40m
     ```

     If there are multiple entries under "ENDPOINTS", then your cluster must have more than one API server.  In this case, use the appropriate load balancing option below for your cluster.

   - If using DNS load balancing (as used by `kops`), use the FQDN and port of the API server `api.internal.<clustername>`.
   - If you have multiple API servers with a load balancer in front, you should use the IP and port of the load balancer.

   > **Tip**: If your cluster uses a ConfigMap to configure `kube-proxy` you can find the "right" way to reach the API
   > server by examining the config map.  For example:
   > ```
   > $ kubectl get configmap -n kube-system kube-proxy -o yaml | grep server`
   >     server: https://d881b853ae312e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com
   > ```
   > In this case, the server is `d881b853aea312e00302a84f1e346a77.gr7.us-west-2.eks.amazonaws.com` and the port is
   > 443 (the standard HTTPS port).
   {: .alert .alert-success}
