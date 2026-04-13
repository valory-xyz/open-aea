The <a href="../api/decision_maker/base#decisionmaker-objects">`DecisionMaker`</a> can be thought of like a wallet manager plus "economic brain" of the AEA. It is responsible for the AEA's crypto-economic security and goal management, and it contains the preference and ownership representation of the AEA. The decision maker is the only component which has access to the wallet's private keys.

## Interaction with skills

Skills communicate with the decision maker via <a href="../api/protocols/base#message-objects">`Messages`</a>. At present, the decision maker processes messages of two protocols:

- <a href="../api/protocols/signing/message#signingmessage-objects">`SigningMessage`</a>: it is used by skills to propose a transaction to the decision-maker for signing.

A message, say `msg`, is sent to the decision maker like so from any skill:
```
self.context.decision_maker_message_queue.put_nowait(msg)
```

The decision maker processes messages and can accept or reject them.

To process `Messages` from the decision maker in a given skill you need to create a `Handler`, in particular a `SigningHandler` like so:

``` python
class SigningHandler(Handler):

	protocol_id = SigningMessage.protocol_id

	def handle(self, message: Message):
		"""
		Handle a signing message.

		:param message: the signing message from the decision maker.
		"""
		# code to handle the message
```

## Custom `DecisionMaker`

The framework implements a default <a href="../api/decision_maker/default#decisionmakerhandler-objects">`DecisionMakerHandler`</a> at `aea.decision_maker.default:DecisionMakerHandler`. No further configuration is needed to use it.

To implement your own, scaffold a custom handler into your AEA project:

``` bash
aea scaffold decision-maker-handler
```

This creates a `decision_maker_handler.py` file in your project root and adds the corresponding entry to `aea-config.yaml`. You can then implement your own custom logic to process messages and interact with the `Wallet`.
