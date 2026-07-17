"""Regression tests for retiring miner-mounted source ConfigMaps."""

from unittest.mock import MagicMock, patch

from chutes_miner.api.k8s.operator import ConfigMapWorker


def _worker(client):
    worker = ConfigMapWorker.__new__(ConfigMapWorker)
    worker._manager = MagicMock()
    worker._manager.get_core_client.return_value = client
    worker._get_request_timeout = MagicMock(return_value=(5, 60))
    return worker


def test_reconnect_sync_purges_legacy_source_configmaps_without_recreating_them():
    client = MagicMock()
    config_map = MagicMock()
    config_map.metadata.name = "chute-code-obsolete"
    client.list_namespaced_config_map.return_value.items = [config_map]
    worker = _worker(client)

    with patch("chutes_miner.api.k8s.operator._is_tee_cluster", return_value=False):
        worker._sync_cluster_configmaps("gpu-node")

    client.list_namespaced_config_map.assert_called_once()
    assert (
        client.list_namespaced_config_map.call_args.kwargs["label_selector"] == "chutes/code=true"
    )
    client.delete_namespaced_config_map.assert_called_once()
    client.create_namespaced_config_map.assert_not_called()


def test_reconnect_cleanup_never_touches_tee_cluster():
    client = MagicMock()
    worker = _worker(client)

    with patch("chutes_miner.api.k8s.operator._is_tee_cluster", return_value=True):
        worker._sync_cluster_configmaps("tee-node")

    client.list_namespaced_config_map.assert_not_called()
    client.delete_namespaced_config_map.assert_not_called()
    client.create_namespaced_config_map.assert_not_called()
