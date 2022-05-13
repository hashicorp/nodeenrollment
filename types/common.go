package types

import (
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

// ValidateMessage contains some common functions that can be used to ensure
// that the message is valid before further processing:
//
// * It's not nil
// * It's a pointer
// * It's a known type
func ValidateMessage(msg proto.Message) error {
	const op = "nodeenrollment.ValidateMessage"
	if msg == nil {
		return fmt.Errorf("(%s) nil message passed in to validate", op)
	}
	switch t := msg.(type) {
	case *FetchNodeCredentialsRequest:
	case *NodeCredentials,
		*NodeInformation,
		*RootCertificate:
		// This should never be an issue as the compiler should catch it, but
		// just an extra check...
		if _, ok := t.(nodeenrollment.MessageWithId); !ok {
			return fmt.Errorf("(%s) message does not satisfy MessageWithId", op)
		}
	default:
		return fmt.Errorf("(%s) unknown message type %T", op, t)
	}
	return nil
}
