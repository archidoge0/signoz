package promotetypes

import (
	"strings"

	"github.com/SigNoz/signoz-otel-collector/pkg/keycheck"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/types/telemetrytypes"
)

type WrappedIndex struct {
	JSONDataType  telemetrytypes.JSONDataType  `json:"-"`
	FieldDataType telemetrytypes.FieldDataType `json:"fieldDataType"`
	Type          string                       `json:"type"`
	Granularity   int                          `json:"granularity"`
}

type PromotePath struct {
	Signal  string `json:"signal"`
	Context string `json:"context"`
	Path    string `json:"path"`
	Promote bool   `json:"promote,omitempty"`

	Indexes []WrappedIndex `json:"indexes,omitempty"`
}

// Target resolves the promotion domain the signal and context name.
func (i *PromotePath) Target() (Target, error) {
	return NewTargetFromText(i.Signal, i.Context)
}

func (i *PromotePath) ValidateAndSetDefaults(target Target) error {
	if i.Path == "" {
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "path is required")
	}

	if strings.Contains(i.Path, " ") {
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "path cannot contain spaces")
	}

	if strings.Contains(i.Path, telemetrytypes.ArraySep) || strings.Contains(i.Path, telemetrytypes.ArrayAnyIndex) {
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "array paths can not be promoted or indexed")
	}

	for _, prefix := range target.RejectedPathPrefixes() {
		if strings.HasPrefix(i.Path, prefix) {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "path must be a bare attribute name, without the `%s` prefix", prefix)
		}
	}

	isCardinal := keycheck.IsCardinal(i.Path)
	if isCardinal {
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "cardinal paths can not be promoted or indexed")
	}

	if len(i.Indexes) > 0 && !target.IndexesSupported {
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "indexes are not supported for %s %s", target.Entry.Signal.StringValue(), target.Entry.FieldContext.StringValue())
	}

	for idx, index := range i.Indexes {
		if index.Type == "" {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "index type is required")
		}
		if index.Granularity <= 0 {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "index granularity must be greater than 0")
		}

		jsonDataType, ok := telemetrytypes.MappingFieldDataTypeToJSONDataType[index.FieldDataType]
		if !ok {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "invalid column type: %s", index.FieldDataType)
		}
		if !jsonDataType.IndexSupported {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "index is not supported for column type: %s", index.FieldDataType)
		}

		i.Indexes[idx].JSONDataType = jsonDataType
	}

	return nil
}
