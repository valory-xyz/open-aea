<a id="aea.test_tools.test_protocol"></a>

# aea.test`_`tools.test`_`protocol

This module contains test case classes based on pytest for AEA protocol testing.

<a id="aea.test_tools.test_protocol.BaseMessageTest"></a>

## BaseMessageTest Objects

```python
class BaseMessageTest()
```

Base class to test one message encode/decode

<a id="aea.test_tools.test_protocol.BaseMessageTest.perform_mesage_test"></a>

#### perform`_`mesage`_`test

```python
def perform_mesage_test(msg: Message) -> None
```

Test message encode/decode.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessageConstruction"></a>

## BaseTestProtocolMessageConstruction Objects

```python
class BaseTestProtocolMessageConstruction(BaseMessageTest)
```

Base class to test message construction for the protocol.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessageConstruction.test_run"></a>

#### test`_`run

```python
def test_run() -> None
```

Run the test.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessageConstruction.build_message"></a>

#### build`_`message

```python
@abstractmethod
def build_message() -> Message
```

Build the message to be used for testing.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages"></a>

## BaseTestProtocolMessages Objects

```python
class BaseTestProtocolMessages(BaseMessageTest)
```

Base class to test messages for the protocol.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages.test_messages_ok"></a>

#### test`_`messages`_`ok

```python
def test_messages_ok() -> None
```

Run messages are ok for encode and decode.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages.test_messages_inconsistent"></a>

#### test`_`messages`_`inconsistent

```python
def test_messages_inconsistent() -> None
```

Run messages are inconsistent.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages.test_messages_fail_to_encode_decode"></a>

#### test`_`messages`_`fail`_`to`_`encode`_`decode

```python
def test_messages_fail_to_encode_decode() -> None
```

Run messages are failing to encode and decode.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages.build_messages"></a>

#### build`_`messages

```python
@abstractmethod
def build_messages() -> List[Message]
```

Build the messages to be used for testing.

<a id="aea.test_tools.test_protocol.BaseTestProtocolMessages.build_inconsistent"></a>

#### build`_`inconsistent

```python
@abstractmethod
def build_inconsistent() -> List[Message]
```

Build inconsistent messages to be used for testing.

<a id="aea.test_tools.test_protocol.BaseTestProtocolDialogues"></a>

## BaseTestProtocolDialogues Objects

```python
class BaseTestProtocolDialogues()
```

Base class to test message construction for the protocol.

<a id="aea.test_tools.test_protocol.BaseTestProtocolDialogues.role_from_first_message"></a>

#### role`_`from`_`first`_`message

```python
def role_from_first_message(message: Message, receiver_address: Address) -> Dialogue.Role
```

Infer the role of the agent from an incoming/outgoing first message

**Arguments**:

- `message`: an incoming/outgoing first message
- `receiver_address`: the address of the receiving agent

**Returns**:

The role of the agent

<a id="aea.test_tools.test_protocol.BaseTestProtocolDialogues.make_dialogues_class"></a>

#### make`_`dialogues`_`class

```python
def make_dialogues_class() -> Type[Dialogues]
```

Make dialogues class with specific role.

<a id="aea.test_tools.test_protocol.BaseTestProtocolDialogues.make_message_content"></a>

#### make`_`message`_`content

```python
@abstractmethod
def make_message_content() -> dict
```

Make a dict with message contruction content for dialogues.create.

<a id="aea.test_tools.test_protocol.BaseTestProtocolDialogues.test_dialogues"></a>

#### test`_`dialogues

```python
def test_dialogues() -> None
```

Test dialogues.
