<a id="aea.protocols.dialogue.base"></a>

# aea.protocols.dialogue.base

This module contains the classes required for dialogue management.

- DialogueLabel: The dialogue label class acts as an identifier for dialogues.
- Dialogue: The dialogue class maintains state of a dialogue and manages it.
- Dialogues: The dialogues class keeps track of all dialogues.

<a id="aea.protocols.dialogue.base.InvalidDialogueMessage"></a>

## InvalidDialogueMessage Objects

```python
class InvalidDialogueMessage(Exception)
```

Exception for adding invalid message to a dialogue.

<a id="aea.protocols.dialogue.base.DialogueLabel"></a>

## DialogueLabel Objects

```python
class DialogueLabel()
```

The dialogue label class acts as an identifier for dialogues.

<a id="aea.protocols.dialogue.base.DialogueLabel.__init__"></a>

#### `__`init`__`

```python
def __init__(dialogue_reference: Tuple[str,
                                       str], dialogue_opponent_addr: Address,
             dialogue_starter_addr: Address) -> None
```

Initialize a dialogue label.

**Arguments**:

- `dialogue_reference`: the reference of the dialogue.
- `dialogue_opponent_addr`: the addr of the agent with which the dialogue is kept.
- `dialogue_starter_addr`: the addr of the agent which started the dialogue.

<a id="aea.protocols.dialogue.base.DialogueLabel.dialogue_reference"></a>

#### dialogue`_`reference

```python
@property
def dialogue_reference() -> Tuple[str, str]
```

Get the dialogue reference.

<a id="aea.protocols.dialogue.base.DialogueLabel.dialogue_starter_reference"></a>

#### dialogue`_`starter`_`reference

```python
@property
def dialogue_starter_reference() -> str
```

Get the dialogue starter reference.

<a id="aea.protocols.dialogue.base.DialogueLabel.dialogue_responder_reference"></a>

#### dialogue`_`responder`_`reference

```python
@property
def dialogue_responder_reference() -> str
```

Get the dialogue responder reference.

<a id="aea.protocols.dialogue.base.DialogueLabel.dialogue_opponent_addr"></a>

#### dialogue`_`opponent`_`addr

```python
@property
def dialogue_opponent_addr() -> str
```

Get the address of the dialogue opponent.

<a id="aea.protocols.dialogue.base.DialogueLabel.dialogue_starter_addr"></a>

#### dialogue`_`starter`_`addr

```python
@property
def dialogue_starter_addr() -> str
```

Get the address of the dialogue starter.

<a id="aea.protocols.dialogue.base.DialogueLabel.__eq__"></a>

#### `__`eq`__`

```python
def __eq__(other: Any) -> bool
```

Check for equality between two DialogueLabel objects.

<a id="aea.protocols.dialogue.base.DialogueLabel.__hash__"></a>

#### `__`hash`__`

```python
def __hash__() -> int
```

Turn object into hash.

<a id="aea.protocols.dialogue.base.DialogueLabel.json"></a>

#### json

```python
@property
def json() -> Dict
```

Return the JSON representation.

<a id="aea.protocols.dialogue.base.DialogueLabel.from_json"></a>

#### from`_`json

```python
@classmethod
def from_json(cls, obj: Dict[str, str]) -> "DialogueLabel"
```

Get dialogue label from json.

<a id="aea.protocols.dialogue.base.DialogueLabel.is_complete"></a>

#### is`_`complete

```python
def is_complete() -> bool
```

Check if the dialogue label is complete.

<a id="aea.protocols.dialogue.base.DialogueLabel.get_incomplete_version"></a>

#### get`_`incomplete`_`version

```python
def get_incomplete_version() -> "DialogueLabel"
```

Get the incomplete version of the label.

<a id="aea.protocols.dialogue.base.DialogueLabel.get_both_versions"></a>

#### get`_`both`_`versions

```python
def get_both_versions() -> Tuple["DialogueLabel", Optional["DialogueLabel"]]
```

Get the incomplete and complete versions of the label.

<a id="aea.protocols.dialogue.base.DialogueLabel.__str__"></a>

#### `__`str`__`

```python
def __str__() -> str
```

Get the string representation.

<a id="aea.protocols.dialogue.base.DialogueLabel.from_str"></a>

#### from`_`str

```python
@classmethod
def from_str(cls, obj: str) -> "DialogueLabel"
```

Get the dialogue label from string representation.

<a id="aea.protocols.dialogue.base._DialogueMeta"></a>

## `_`DialogueMeta Objects

```python
class _DialogueMeta(type)
```

Metaclass for Dialogue.

Creates class level Rules instance to share among instances

<a id="aea.protocols.dialogue.base._DialogueMeta.__new__"></a>

#### `__`new`__`

```python
def __new__(mcs, name: str, bases: Tuple[Type], dct: Dict) -> "_DialogueMeta"
```

Construct a new type.

<a id="aea.protocols.dialogue.base.Dialogue"></a>

## Dialogue Objects

```python
class Dialogue(metaclass=_DialogueMeta)
```

The dialogue class maintains state of a dialogue and manages it.

<a id="aea.protocols.dialogue.base.Dialogue.INITIAL_PERFORMATIVES"></a>

#### INITIAL`_`PERFORMATIVES

type: FrozenSet[Message.Performative]

<a id="aea.protocols.dialogue.base.Dialogue.TERMINAL_PERFORMATIVES"></a>

#### TERMINAL`_`PERFORMATIVES

type: FrozenSet[Message.Performative]

<a id="aea.protocols.dialogue.base.Dialogue.VALID_REPLIES"></a>

#### VALID`_`REPLIES

type: Dict[Message.Performative, FrozenSet[Message.Performative]]

<a id="aea.protocols.dialogue.base.Dialogue.Rules"></a>

## Rules Objects

```python
class Rules()
```

This class defines the rules for the dialogue.

<a id="aea.protocols.dialogue.base.Dialogue.Rules.__init__"></a>

#### `__`init`__`

```python
def __init__(
    initial_performatives: FrozenSet[Message.Performative],
    terminal_performatives: FrozenSet[Message.Performative],
    valid_replies: Dict[Message.Performative, FrozenSet[Message.Performative]]
) -> None
```

Initialize a dialogue.

**Arguments**:

- `initial_performatives`: the set of all initial performatives.
- `terminal_performatives`: the set of all terminal performatives.
- `valid_replies`: the reply structure of speech-acts.

<a id="aea.protocols.dialogue.base.Dialogue.Rules.initial_performatives"></a>

#### initial`_`performatives

```python
@property
def initial_performatives() -> FrozenSet[Message.Performative]
```

Get the performatives one of which the terminal message in the dialogue must have.

**Returns**:

the valid performatives of an terminal message

<a id="aea.protocols.dialogue.base.Dialogue.Rules.terminal_performatives"></a>

#### terminal`_`performatives

```python
@property
def terminal_performatives() -> FrozenSet[Message.Performative]
```

Get the performatives one of which the terminal message in the dialogue must have.

**Returns**:

the valid performatives of an terminal message

<a id="aea.protocols.dialogue.base.Dialogue.Rules.valid_replies"></a>

#### valid`_`replies

```python
@property
def valid_replies(
) -> Dict[Message.Performative, FrozenSet[Message.Performative]]
```

Get all the valid performatives which are a valid replies to performatives.

**Returns**:

the full valid reply structure.

<a id="aea.protocols.dialogue.base.Dialogue.Rules.get_valid_replies"></a>

#### get`_`valid`_`replies

```python
def get_valid_replies(
        performative: Message.Performative) -> FrozenSet[Message.Performative]
```

Given a `performative`, return the list of performatives which are its valid replies in a dialogue.

**Arguments**:

- `performative`: the performative in a message

**Returns**:

list of valid performative replies

<a id="aea.protocols.dialogue.base.Dialogue.Role"></a>

## Role Objects

```python
class Role(Enum)
```

This class defines the agent's role in a dialogue.

<a id="aea.protocols.dialogue.base.Dialogue.Role.__str__"></a>

#### `__`str`__`

```python
def __str__() -> str
```

Get the string representation.

<a id="aea.protocols.dialogue.base.Dialogue.EndState"></a>

## EndState Objects

```python
class EndState(Enum)
```

This class defines the end states of a dialogue.

<a id="aea.protocols.dialogue.base.Dialogue.EndState.__str__"></a>

#### `__`str`__`

```python
def __str__() -> str
```

Get the string representation.

<a id="aea.protocols.dialogue.base.Dialogue.__init__"></a>

#### `__`init`__`

```python
def __init__(dialogue_label: DialogueLabel, message_class: Type[Message],
             self_address: Address, role: Role) -> None
```

Initialize a dialogue.

**Arguments**:

- `dialogue_label`: the identifier of the dialogue
- `message_class`: the message class used
- `self_address`: the address of the entity for whom this dialogue is maintained
- `role`: the role of the agent this dialogue is maintained for

<a id="aea.protocols.dialogue.base.Dialogue.add_terminal_state_callback"></a>

#### add`_`terminal`_`state`_`callback

```python
def add_terminal_state_callback(fn: Callable[["Dialogue"], None]) -> None
```

Add callback to be called on dialogue reach terminal state.

**Arguments**:

- `fn`: callable to be called with one argument: Dialogue

<a id="aea.protocols.dialogue.base.Dialogue.__eq__"></a>

#### `__`eq`__`

```python
def __eq__(other: Any) -> bool
```

Compare two dialogues.

<a id="aea.protocols.dialogue.base.Dialogue.json"></a>

#### json

```python
def json() -> dict
```

Get json representation of the dialogue.

<a id="aea.protocols.dialogue.base.Dialogue.from_json"></a>

#### from`_`json

```python
@classmethod
def from_json(cls, message_class: Type[Message], data: dict) -> "Dialogue"
```

Create a dialogue instance with all messages from json data.

**Arguments**:

- `message_class`: type of message used with this dialogue
- `data`: dict with data exported with Dialogue.to_json() method

**Returns**:

Dialogue instance

<a id="aea.protocols.dialogue.base.Dialogue.dialogue_label"></a>

#### dialogue`_`label

```python
@property
def dialogue_label() -> DialogueLabel
```

Get the dialogue label.

**Returns**:

The dialogue label

<a id="aea.protocols.dialogue.base.Dialogue.incomplete_dialogue_label"></a>

#### incomplete`_`dialogue`_`label

```python
@property
def incomplete_dialogue_label() -> DialogueLabel
```

Get the dialogue label.

**Returns**:

The incomplete dialogue label

<a id="aea.protocols.dialogue.base.Dialogue.dialogue_labels"></a>

#### dialogue`_`labels

```python
@property
def dialogue_labels() -> Set[DialogueLabel]
```

Get the dialogue labels (incomplete and complete, if it exists).

**Returns**:

the dialogue labels

<a id="aea.protocols.dialogue.base.Dialogue.self_address"></a>

#### self`_`address

```python
@property
def self_address() -> Address
```

Get the address of the entity for whom this dialogues is maintained.

**Returns**:

the address of this entity

<a id="aea.protocols.dialogue.base.Dialogue.role"></a>

#### role

```python
@property
def role() -> "Role"
```

Get the agent's role in the dialogue.

**Returns**:

the agent's role

<a id="aea.protocols.dialogue.base.Dialogue.rules"></a>

#### rules

```python
@property
def rules() -> "Rules"
```

Get the dialogue rules.

**Returns**:

the rules

<a id="aea.protocols.dialogue.base.Dialogue.message_class"></a>

#### message`_`class

```python
@property
def message_class() -> Type[Message]
```

Get the message class.

**Returns**:

the message class

<a id="aea.protocols.dialogue.base.Dialogue.is_self_initiated"></a>

#### is`_`self`_`initiated

```python
@property
def is_self_initiated() -> bool
```

Check whether the agent initiated the dialogue.

**Returns**:

True if the agent initiated the dialogue, False otherwise

<a id="aea.protocols.dialogue.base.Dialogue.last_incoming_message"></a>

#### last`_`incoming`_`message

```python
@property
def last_incoming_message() -> Optional[Message]
```

Get the last incoming message.

**Returns**:

the last incoming message if it exists, None otherwise

<a id="aea.protocols.dialogue.base.Dialogue.last_outgoing_message"></a>

#### last`_`outgoing`_`message

```python
@property
def last_outgoing_message() -> Optional[Message]
```

Get the last outgoing message.

**Returns**:

the last outgoing message if it exists, None otherwise

<a id="aea.protocols.dialogue.base.Dialogue.last_message"></a>

#### last`_`message

```python
@property
def last_message() -> Optional[Message]
```

Get the last message.

**Returns**:

the last message if it exists, None otherwise

<a id="aea.protocols.dialogue.base.Dialogue.is_empty"></a>

#### is`_`empty

```python
@property
def is_empty() -> bool
```

Check whether the dialogue is empty.

**Returns**:

True if empty, False otherwise

<a id="aea.protocols.dialogue.base.Dialogue.reply"></a>

#### reply

```python
def reply(performative: Message.Performative,
          target_message: Optional[Message] = None,
          target: Optional[int] = None,
          **kwargs: Any) -> Message
```

Reply to the 'target_message' in this dialogue with a message with 'performative', and contents from kwargs.

Note if no target_message is provided, the last message in the dialogue will be replied to.

**Arguments**:

- `target_message`: the message to reply to.
- `target`: the id of the message to reply to.
- `performative`: the performative of the reply message.
- `kwargs`: the content of the reply message.

**Returns**:

the reply message if it was successfully added as a reply, None otherwise.

<a id="aea.protocols.dialogue.base.Dialogue.get_message_by_id"></a>

#### get`_`message`_`by`_`id

```python
def get_message_by_id(message_id: int) -> Optional[Message]
```

Get message by id, if not presents return None.

<a id="aea.protocols.dialogue.base.Dialogue.get_outgoing_next_message_id"></a>

#### get`_`outgoing`_`next`_`message`_`id

```python
def get_outgoing_next_message_id() -> int
```

Get next outgoing message id.

<a id="aea.protocols.dialogue.base.Dialogue.get_incoming_next_message_id"></a>

#### get`_`incoming`_`next`_`message`_`id

```python
def get_incoming_next_message_id() -> int
```

Get next incoming message id.

<a id="aea.protocols.dialogue.base.Dialogue.__str__"></a>

#### `__`str`__`

```python
def __str__() -> str
```

Get the string representation.

**Returns**:

The string representation of the dialogue

<a id="aea.protocols.dialogue.base.DialogueStats"></a>

## DialogueStats Objects

```python
class DialogueStats()
```

Class to handle statistics on default dialogues.

<a id="aea.protocols.dialogue.base.DialogueStats.__init__"></a>

#### `__`init`__`

```python
def __init__(end_states: FrozenSet[Dialogue.EndState]) -> None
```

Initialize a StatsManager.

**Arguments**:

- `end_states`: the list of dialogue endstates

<a id="aea.protocols.dialogue.base.DialogueStats.self_initiated"></a>

#### self`_`initiated

```python
@property
def self_initiated() -> Dict[Dialogue.EndState, int]
```

Get the stats dictionary on self initiated dialogues.

<a id="aea.protocols.dialogue.base.DialogueStats.other_initiated"></a>

#### other`_`initiated

```python
@property
def other_initiated() -> Dict[Dialogue.EndState, int]
```

Get the stats dictionary on other initiated dialogues.

<a id="aea.protocols.dialogue.base.DialogueStats.add_dialogue_endstate"></a>

#### add`_`dialogue`_`endstate

```python
def add_dialogue_endstate(end_state: Dialogue.EndState,
                          is_self_initiated: bool) -> None
```

Add dialogue endstate stats.

**Arguments**:

- `end_state`: the end state of the dialogue
- `is_self_initiated`: whether the dialogue is initiated by the agent or the opponent

<a id="aea.protocols.dialogue.base.find_caller_object"></a>

#### find`_`caller`_`object

```python
def find_caller_object(object_type: Type) -> Any
```

Find caller object of certain type in the call stack.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage"></a>

## BasicDialoguesStorage Objects

```python
class BasicDialoguesStorage()
```

Dialogues state storage.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.__init__"></a>

#### `__`init`__`

```python
def __init__(dialogues: "Dialogues") -> None
```

Init dialogues storage.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.cleanup"></a>

#### cleanup

```python
def cleanup() -> None
```

Clean up the dialogue storage

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.dialogues_in_terminal_state"></a>

#### dialogues`_`in`_`terminal`_`state

```python
@property
def dialogues_in_terminal_state() -> List["Dialogue"]
```

Get all dialogues in terminal state.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.dialogues_in_active_state"></a>

#### dialogues`_`in`_`active`_`state

```python
@property
def dialogues_in_active_state() -> List["Dialogue"]
```

Get all dialogues in active state.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.is_terminal_dialogues_kept"></a>

#### is`_`terminal`_`dialogues`_`kept

```python
@property
def is_terminal_dialogues_kept() -> bool
```

Return True if dialogues should stay after terminal state.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.dialogue_terminal_state_callback"></a>

#### dialogue`_`terminal`_`state`_`callback

```python
def dialogue_terminal_state_callback(dialogue: "Dialogue") -> None
```

Method to be called on dialogue terminal state reached.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.setup"></a>

#### setup

```python
def setup() -> None
```

Set up dialogue storage.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.teardown"></a>

#### teardown

```python
def teardown() -> None
```

Tear down dialogue storage.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.add"></a>

#### add

```python
def add(dialogue: Dialogue) -> None
```

Add dialogue to storage.

Label can be complete (if receiving a message, and `add` being called by `Dialogue.update`)
or incomplete (if sending a message, and `add` being called by `Dialogue.create`).

**Arguments**:

- `dialogue`: dialogue to add.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.remove"></a>

#### remove

```python
def remove(dialogue_label: DialogueLabel) -> None
```

Remove dialogue from storage by it's label.

**Arguments**:

- `dialogue_label`: label of the dialogue to remove

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.get"></a>

#### get

```python
def get(dialogue_label: DialogueLabel) -> Optional[Dialogue]
```

Get dialogue stored by it's label.

**Arguments**:

- `dialogue_label`: label of the dialogue

**Returns**:

dialogue if presents or None

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.get_dialogues_with_counterparty"></a>

#### get`_`dialogues`_`with`_`counterparty

```python
def get_dialogues_with_counterparty(counterparty: Address) -> List[Dialogue]
```

Get the dialogues by address.

**Arguments**:

- `counterparty`: the counterparty

**Returns**:

The dialogues with the counterparty.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.is_in_incomplete"></a>

#### is`_`in`_`incomplete

```python
def is_in_incomplete(dialogue_label: DialogueLabel) -> bool
```

Check dialogue label presents in list of incomplete.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.set_incomplete_dialogue"></a>

#### set`_`incomplete`_`dialogue

```python
def set_incomplete_dialogue(incomplete_dialogue_label: DialogueLabel,
                            complete_dialogue_label: DialogueLabel) -> None
```

Set incomplete dialogue label.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.is_dialogue_present"></a>

#### is`_`dialogue`_`present

```python
def is_dialogue_present(dialogue_label: DialogueLabel) -> bool
```

Check dialogue with label specified presents in storage.

<a id="aea.protocols.dialogue.base.BasicDialoguesStorage.get_latest_label"></a>

#### get`_`latest`_`label

```python
def get_latest_label(dialogue_label: DialogueLabel) -> DialogueLabel
```

Get latest label for dialogue.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage"></a>

## PersistDialoguesStorage Objects

```python
class PersistDialoguesStorage(BasicDialoguesStorage)
```

Persist dialogues storage.

Uses generic storage to load/save dialogues data on setup/teardown.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage.__init__"></a>

#### `__`init`__`

```python
def __init__(dialogues: "Dialogues") -> None
```

Init dialogues storage.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage.get_skill_component"></a>

#### get`_`skill`_`component

```python
@staticmethod
def get_skill_component() -> Optional[SkillComponent]
```

Get skill component dialogues storage constructed for.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage.setup"></a>

#### setup

```python
def setup() -> None
```

Set up dialogue storage.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage.teardown"></a>

#### teardown

```python
def teardown() -> None
```

Tear down dialogue storage.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorage.remove"></a>

#### remove

```python
def remove(dialogue_label: DialogueLabel) -> None
```

Remove dialogue from memory and persistent storage.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorageWithOffloading"></a>

## PersistDialoguesStorageWithOffloading Objects

```python
class PersistDialoguesStorageWithOffloading(PersistDialoguesStorage)
```

Dialogue Storage with dialogues offloading.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorageWithOffloading.dialogue_terminal_state_callback"></a>

#### dialogue`_`terminal`_`state`_`callback

```python
def dialogue_terminal_state_callback(dialogue: "Dialogue") -> None
```

Call on dialogue reaches terminal state.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorageWithOffloading.get"></a>

#### get

```python
def get(dialogue_label: DialogueLabel) -> Optional[Dialogue]
```

Try to get dialogue by label from memory or persists storage.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorageWithOffloading.get_dialogues_with_counterparty"></a>

#### get`_`dialogues`_`with`_`counterparty

```python
def get_dialogues_with_counterparty(counterparty: Address) -> List[Dialogue]
```

Get the dialogues by address.

**Arguments**:

- `counterparty`: the counterparty

**Returns**:

The dialogues with the counterparty.

<a id="aea.protocols.dialogue.base.PersistDialoguesStorageWithOffloading.dialogues_in_terminal_state"></a>

#### dialogues`_`in`_`terminal`_`state

```python
@property
def dialogues_in_terminal_state() -> List["Dialogue"]
```

Get all dialogues in terminal state.

<a id="aea.protocols.dialogue.base.Dialogues"></a>

## Dialogues Objects

```python
class Dialogues()
```

The dialogues class keeps track of all dialogues for an agent.

<a id="aea.protocols.dialogue.base.Dialogues.__init__"></a>

#### `__`init`__`

```python
def __init__(self_address: Address,
             end_states: FrozenSet[Dialogue.EndState],
             message_class: Type[Message],
             dialogue_class: Type[Dialogue],
             role_from_first_message: Callable[[Message, Address],
                                               Dialogue.Role],
             keep_terminal_state_dialogues: Optional[bool] = None) -> None
```

Initialize dialogues.

**Arguments**:

- `self_address`: the address of the entity for whom dialogues are maintained
- `end_states`: the list of dialogue endstates
- `message_class`: the message class used
- `dialogue_class`: the dialogue class used
- `role_from_first_message`: the callable determining role from first message
- `keep_terminal_state_dialogues`: specify do dialogues in terminal state should stay or not

<a id="aea.protocols.dialogue.base.Dialogues.cleanup"></a>

#### cleanup

```python
def cleanup() -> None
```

Clean up the dialogue storage

<a id="aea.protocols.dialogue.base.Dialogues.is_keep_dialogues_in_terminal_state"></a>

#### is`_`keep`_`dialogues`_`in`_`terminal`_`state

```python
@property
def is_keep_dialogues_in_terminal_state() -> bool
```

Is required to keep dialogues in terminal state.

<a id="aea.protocols.dialogue.base.Dialogues.self_address"></a>

#### self`_`address

```python
@property
def self_address() -> Address
```

Get the address of the agent for whom dialogues are maintained.

<a id="aea.protocols.dialogue.base.Dialogues.dialogue_stats"></a>

#### dialogue`_`stats

```python
@property
def dialogue_stats() -> DialogueStats
```

Get the dialogue statistics.

**Returns**:

dialogue stats object

<a id="aea.protocols.dialogue.base.Dialogues.message_class"></a>

#### message`_`class

```python
@property
def message_class() -> Type[Message]
```

Get the message class.

**Returns**:

the message class

<a id="aea.protocols.dialogue.base.Dialogues.dialogue_class"></a>

#### dialogue`_`class

```python
@property
def dialogue_class() -> Type[Dialogue]
```

Get the dialogue class.

**Returns**:

the dialogue class

<a id="aea.protocols.dialogue.base.Dialogues.get_dialogues_with_counterparty"></a>

#### get`_`dialogues`_`with`_`counterparty

```python
def get_dialogues_with_counterparty(counterparty: Address) -> List[Dialogue]
```

Get the dialogues by address.

**Arguments**:

- `counterparty`: the counterparty

**Returns**:

The dialogues with the counterparty.

<a id="aea.protocols.dialogue.base.Dialogues.new_self_initiated_dialogue_reference"></a>

#### new`_`self`_`initiated`_`dialogue`_`reference

```python
@classmethod
def new_self_initiated_dialogue_reference(cls) -> Tuple[str, str]
```

Return a dialogue label for a new self initiated dialogue.

**Returns**:

the next nonce

<a id="aea.protocols.dialogue.base.Dialogues.create"></a>

#### create

```python
def create(counterparty: Address, performative: Message.Performative,
           **kwargs: Any) -> Tuple[Message, Dialogue]
```

Create a dialogue with 'counterparty', with an initial message whose performative is 'performative' and contents are from 'kwargs'.

**Arguments**:

- `counterparty`: the counterparty of the dialogue.
- `performative`: the performative of the initial message.
- `kwargs`: the content of the initial message.

**Returns**:

the initial message and the dialogue.

<a id="aea.protocols.dialogue.base.Dialogues.create_with_message"></a>

#### create`_`with`_`message

```python
def create_with_message(counterparty: Address,
                        initial_message: Message) -> Dialogue
```

Create a dialogue with 'counterparty', with an initial message provided.

**Arguments**:

- `counterparty`: the counterparty of the dialogue.
- `initial_message`: the initial_message.

**Returns**:

the initial message and the dialogue.

<a id="aea.protocols.dialogue.base.Dialogues.update"></a>

#### update

```python
def update(message: Message) -> Optional[Dialogue]
```

Update the state of dialogues with a new incoming message.

If the message is for a new dialogue, a new dialogue is created with 'message' as its first message, and returned.
If the message is addressed to an existing dialogue, the dialogue is retrieved, extended with this message and returned.
If there are any errors, e.g. the message dialogue reference does not exists or the message is invalid w.r.t. the dialogue, return None.

**Arguments**:

- `message`: a new incoming message

**Returns**:

the new or existing dialogue the message is intended for, or None in case of any errors.

<a id="aea.protocols.dialogue.base.Dialogues.get_dialogue"></a>

#### get`_`dialogue

```python
def get_dialogue(message: Message) -> Optional[Dialogue]
```

Retrieve the dialogue 'message' belongs to.

**Arguments**:

- `message`: a message

**Returns**:

the dialogue, or None in case such a dialogue does not exist

<a id="aea.protocols.dialogue.base.Dialogues.get_dialogue_from_label"></a>

#### get`_`dialogue`_`from`_`label

```python
def get_dialogue_from_label(
        dialogue_label: DialogueLabel) -> Optional[Dialogue]
```

Retrieve a dialogue based on its label.

**Arguments**:

- `dialogue_label`: the dialogue label

**Returns**:

the dialogue if present

<a id="aea.protocols.dialogue.base.Dialogues.setup"></a>

#### setup

```python
def setup() -> None
```

Set  up.

<a id="aea.protocols.dialogue.base.Dialogues.teardown"></a>

#### teardown

```python
def teardown() -> None
```

Tear down.

