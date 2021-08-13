> As discussed [here](https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html){:target="_blank"}, AWS CNI provisions multiple ENIs per node as the number of pods on the node increases.
> AWS CNI will add entries for the primary ENI into the main routing table, and will then create routing tables for each additional ENI, starting at index 2. Additionally, if VLANs are being used, it appears that AWS CNI will use tables from 100 onwards.
> By default, Felix considers routing table indexes from 1-250 to be under its control, and hence will remove the routing tables created by AWS CNI. This can cause loss of connectivity between pods if they are not on the primary ENI.
>
> **Note**: The following steps will result in loss of connectivity between some pods. It is recommended to only make such changes during a maintenance window.
> To ensure that AWS CNI and Felix manage separate ranges of routing tables, you must do the following:
>
> 1. Configure Felix to manage a routing table range which is distinct from the range used by AWS CNI:
>     ```bash
>     kubectl patch felixconfiguration default --type='merge' -p '{"spec": {"routeTableRange":{"min": 65, "max": 99}}}'
>     ````
>
> 1. Delete any routing rules and tables in the range 1-30 as they could be damaged or incomplete
>
> 1. Kill all the aws-node pods, which will force AWS CNI to recreate its routing rules and tables. 
{: .alert .alert-info}