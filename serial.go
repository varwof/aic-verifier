// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"fmt"
	"math/big"
)

// NormalizeSerial converts a certificate serial number to standard hex format
// (uppercase, no 0x prefix, zero-padded to 40 characters).
func NormalizeSerial(serial *big.Int) string {
	return fmt.Sprintf("%040X", serial)
}
