package types

import (
	"fmt"
	reflect "reflect"

	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

// ValidateMsg contains some common functions that can be used to ensure that
// the message is valid before further processing:
//
// * It's not nil
// * It's a pointer
// * It's a known type
func ValidateMsg(msg proto.Message) error {
	const op = "nodeenrollment.ValidateMsg"
	if msg == nil {
		return fmt.Errorf("(%s) nil message passed in to validate", op)
	}
	if reflect.TypeOf(msg).Kind() != reflect.Pointer {
		return fmt.Errorf("(%s) input message is not a pointer", op)
	}
	switch t := msg.(type) {
	case *FetchNodeCredentialsRequest:
	case *NodeCredentials,
		*NodeInformation,
		*RootCertificate:
		if _, ok := t.(nodeenrollment.MessageWithId); !ok {
			return fmt.Errorf("(%s) message does not satisfy MessageWithId", op)
		}
	default:
		return fmt.Errorf("(%s) unknown message type %T", op, t)
	}
	return nil
}
