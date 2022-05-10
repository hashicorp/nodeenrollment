package file

// getFileStorageOpts iterates the inbound Options and returns a struct
func getOpts(opt ...FileStorageOption) (*FileStorageOptions, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}

	}
	return opts, nil
}

type FileStorageOptions struct {
	withBaseDirectory string
	withSkipCleanup   bool
}

// FileStorageOption is a function that takes in an options struct and sets values or
// returns an error.
type FileStorageOption func(*FileStorageOptions) error

func getDefaultOptions() *FileStorageOptions {
	return &FileStorageOptions{}
}

// WithFileStorageBaseDirectory allows specifying a base directory to use
func WithFileStorageBaseDirectory(with string) FileStorageOption {
	return func(o *FileStorageOptions) error {
		o.withBaseDirectory = with
		return nil
	}
}

// WithFileStorageSkipCleanup causes FileStorageStorage cleanup to be a no-op, useful for
// inspecting state after the fact
func WithFileStorageSkipCleanup(with bool) FileStorageOption {
	return func(o *FileStorageOptions) error {
		o.withSkipCleanup = with
		return nil
	}
}
