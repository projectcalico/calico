class NoEndpointForContainer(Exception):
    """
    Tried to get the endpoint associated with a container that has no
    endpoints.
    """
    pass


class DataStoreError(Exception):
    """
    General Datastore exception.
    """
    pass


class ProfileNotInEndpoint(Exception):
    """
    Attempting to remove a profile that is not in the container endpoint
    profile list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class ProfileAlreadyInEndpoint(Exception):
    """
    Attempting to append a profile that is already in the container endpoint
    profile list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class MultipleEndpointsMatch(Exception):
    """
    More than one endpoint was found for the specified criteria.
    """
    pass