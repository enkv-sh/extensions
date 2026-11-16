package output

// Action identifies one of the six output actions; its zero value is invalid.
type Action uint8

// EntryState reports whether provider-effect entry was excluded or may have
// occurred. Its zero value is invalid; it does not grant send permission.
type EntryState uint8

// OutcomeClass is the closed strength of a provider claim. Zero is ClassUnproved;
// acknowledgement is not proof of a selected state change or safe retry.
type OutcomeClass uint8

// Valid reports whether v names one of the six output actions.
func (v Action) Valid() bool { return v >= ActionCreateEmpty && v <= ActionDeleteReservedSlot }

// Valid reports whether v is a defined provider-entry state.
func (v EntryState) Valid() bool { return v == EntryNotEntered || v == EntryMayHaveEntered }

// Valid reports whether v is a defined outcome class, including ClassUnproved.
func (v OutcomeClass) Valid() bool { return v <= ClassQualifiedNoEffect }
