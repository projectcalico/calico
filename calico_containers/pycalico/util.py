def generate_cali_interface_name(prefix, ep_id):
    """Helper method to generate a name for a calico veth, given the endpoint ID

    This takes a prefix, and then truncates the EP ID.

    :param prefix: T
    :param ep_id:
    :return:
    """
    if len(prefix) > 4:
        raise ValueError('Prefix must be 4 characters or less.')
    return prefix + ep_id[:11]
