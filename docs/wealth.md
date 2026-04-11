
To fund an AEA for testing on a test-net you need to request some test tokens from a faucet for your target network.

First, make sure you have installed the crypto plugin of the target test-net. E.g. for Ethereum:
``` bash
pip install open-aea-ledger-ethereum
```

Add a private key to the agent:
``` bash
aea generate-key ethereum
aea add-key ethereum ethereum_private_key.txt
```

<div class="admonition note">
  <p class="admonition-title">Note</p>
  <p>If you already have keys in your project, the commands will prompt you for confirmation whether or not to replace the existing keys.
</p>
</div>

## Using a faucet website

Print the address of your agent:
``` bash
aea get-address ethereum
```

Copy the address and request test tokens from a faucet for your chosen test network (for example, Sepolia, Holesky, or another Ethereum test network). It may take a while for the tokens to become available.

After the faucet has sent the funds, check the wealth associated with the address:
``` bash
aea get-wealth ethereum
```

## Using the CLI

If your chosen test network exposes a programmatic faucet endpoint, you can request funds directly via the CLI by passing the faucet URL:

``` bash
aea generate-wealth ethereum <FAUCET_URL>
```

The `--sync` flag makes the command wait until the faucet has released the funds.
