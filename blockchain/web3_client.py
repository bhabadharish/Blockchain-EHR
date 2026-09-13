"""
blockchain/web3_client.py
Web3.py Client & Local Ganache Network Manager.
Connects to local Ganache RPC endpoint, tracks network status, accounts, blocks, and gas.
"""

import time
from typing import Dict, Any, List, Optional, Tuple

try:
    from web3 import Web3
    WEB3_LIB_AVAILABLE = True
except ImportError:
    WEB3_LIB_AVAILABLE = False


class Web3Client:
    """Manages Web3 connection to local Ganache or testnet RPC."""

    DEFAULT_ENDPOINTS = [
        "http://127.0.0.1:8545",
        "http://localhost:8545",
        "http://127.0.0.1:7545",
        "http://localhost:7545"
    ]

    def __init__(self, rpc_url: Optional[str] = None):
        self.w3: Optional[Any] = None
        self.rpc_url = rpc_url
        self.is_connected = False
        self._init_connection(rpc_url)

    def _init_connection(self, custom_url: Optional[str]):
        if not WEB3_LIB_AVAILABLE:
            self.is_connected = False
            return

        urls_to_try = [custom_url] if custom_url else self.DEFAULT_ENDPOINTS
        for url in urls_to_try:
            if not url:
                continue
            try:
                provider = Web3.HTTPProvider(url, request_kwargs={'timeout': 1.0})
                w3 = Web3(provider)
                if w3.is_connected():
                    self.w3 = w3
                    self.rpc_url = url
                    self.is_connected = True
                    break
            except Exception:
                continue

    def get_network_status(self) -> Dict[str, Any]:
        """Returns live connection status and network KPIs."""
        if not self.is_connected or self.w3 is None:
            return {
                "status": "DISCONNECTED (LOCAL FALLBACK MODE ACTIVE)",
                "is_connected": False,
                "rpc_url": self.rpc_url or "http://127.0.0.1:8545",
                "network_id": None,
                "chain_id": None,
                "current_block": 0,
                "accounts_count": 0,
                "primary_account": None,
                "account_balance_eth": 0.0,
                "gas_price_gwei": 0.0
            }

        try:
            accounts = self.w3.eth.accounts
            primary = accounts[0] if len(accounts) > 0 else None
            bal = self.w3.from_wei(self.w3.eth.get_balance(primary), 'ether') if primary else 0.0
            block_num = self.w3.eth.block_number
            gas_price = self.w3.from_wei(self.w3.eth.gas_price, 'gwei')

            return {
                "status": "CONNECTED (GANACHE LOCAL ETHEREUM NODE)",
                "is_connected": True,
                "rpc_url": self.rpc_url,
                "network_id": getattr(self.w3.net, "version", "1337"),
                "chain_id": getattr(self.w3.eth, "chain_id", 1337),
                "current_block": block_num,
                "accounts_count": len(accounts),
                "primary_account": primary,
                "account_balance_eth": round(float(bal), 4),
                "gas_price_gwei": float(gas_price)
            }
        except Exception as ex:
            return {
                "status": f"CONNECTION_ERROR: {ex}",
                "is_connected": False,
                "rpc_url": self.rpc_url
            }

    def get_recent_blocks(self, count: int = 10) -> List[Dict[str, Any]]:
        """Fetches metadata for the most recently mined blocks."""
        if not self.is_connected or self.w3 is None:
            return []

        blocks = []
        try:
            curr = self.w3.eth.block_number
            start = max(0, curr - count + 1)
            for num in range(curr, start - 1, -1):
                b = self.w3.eth.get_block(num, full_transactions=True)
                blocks.append({
                    "block_number": b.number,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(b.timestamp)),
                    "tx_count": len(b.transactions),
                    "block_hash": b.hash.hex(),
                    "parent_hash": b.parentHash.hex(),
                    "gas_used": b.gasUsed
                })
        except Exception:
            pass
        return blocks
