// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rotation

import (
	"context"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/types"
)

// RotateNodeCredentials accepts a request containing an encrypted fetch node
// credentials request and expects to be able to decrypt it via the key ID from
// the contained value. If valid, the credentials contained in the request will
// be registered to the system as valid credentials.
//
// Note that unlike RotateRootCertificates, where ownership of the roots belongs
// to this library, this is not a method that does nothing if it is not time to
// rotate. The node owns its credentials and should track when it's time to
// rotate and initiate rotation at that time.
//
// Although WithState is not explicitly supported, keep in mind that State will
// be transferred to the new NodeInformation. This fact can be used to match the
// new credentials to an external ID corresponding to the current credentials.
//
// Supported options:
// WithStorageWrapper/WithRandomReader/WithNotBeforeClockSkew/WithNotAfterClockSkew
// (passed through to AuthorizeNode and others), WithLogger
func RotateNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.RotateNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.RotateNodeCredentialsResponse, error) {
	const op = "nodeenrollment.rotation.RotateNodeCredentials"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	case len(req.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) nil certificate public key", op)
	case len(req.EncryptedFetchNodeCredentialsRequest) == 0:
		return nil, fmt.Errorf("(%s) nil encrypted fetch node credentials request", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	currentKeyId, err := nodeenrollment.KeyIdFromPkix(req.CertificatePublicKeyPkix)
	if err != nil {
		err := fmt.Errorf("error deriving current key id: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// Update options for rotation to remove unused credentials, if found
	rotateOpts := make([]nodeenrollment.Option, len(opt))
	copy(rotateOpts, opt)
	rotateOpts = append(rotateOpts, nodeenrollment.WithRemoveUnusedCredentials(true))

	// First we get our current node information and decrypt the fetch request
	currentNodeInfo, err := types.LoadNodeInformation(ctx, storage, currentKeyId, rotateOpts...)
	if err != nil {
		err := fmt.Errorf("error loading current node information: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	fetchRequest := new(types.FetchNodeCredentialsRequest)
	if err := nodeenrollment.DecryptMessage(
		ctx,
		req.EncryptedFetchNodeCredentialsRequest,
		currentNodeInfo,
		fetchRequest,
		opt...,
	); err != nil {
		err := fmt.Errorf("error decrypting request with current keys: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// At this point we've validated via the shared encryption key that it came
	// from that node so we trust the request. First we send it through
	// AuthorizeNode to register it and derive new keys; then, we call a fetch
	// on it and return the result, encrypted with the new keys.
	_, err = registration.AuthorizeNode(ctx, storage, fetchRequest, append(opt, nodeenrollment.WithState(currentNodeInfo.State))...)
	if err != nil {
		err := fmt.Errorf("error authorizing node with request: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// We can use the same request as it is signed/valid. This will be encrypted
	// against the _new_ keys.
	fetchResp, err := registration.FetchNodeCredentials(ctx, storage, fetchRequest, opt...)
	if err != nil {
		err := fmt.Errorf("error getting new fetch credentials response: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// Wrap that new message in one encrypted with the current keys
	encryptedResp, err := nodeenrollment.EncryptMessage(ctx, fetchResp, currentNodeInfo, opt...)
	if err != nil {
		err := fmt.Errorf("error encrypting fetch credentials response: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	return &types.RotateNodeCredentialsResponse{
		EncryptedFetchNodeCredentialsResponse: encryptedResp,
	}, nil
}
