from .QRadarAQL import QRadarAQLBackend


# Mapping between backend identifiers and classes. This is used by the pySigma plugin
# system to recognize backends and expose them with the identifier.
backends = {
    "ibm-qradar-aql": QRadarAQLBackend,
}
