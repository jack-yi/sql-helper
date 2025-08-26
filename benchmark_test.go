package sqlhelper

import (
	"strings"
	"testing"
)

// BenchmarkOldVsNewSystem 对比旧系统和新类型感知系统的性能
func BenchmarkOldVsNewSystem(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"短ID", "project_123"},
		{"中文名称", "北京朝阳区某某项目"},
		{"长描述", strings.Repeat("这是一个项目描述", 100)},
		{"SQL注入攻击", "'; DROP TABLE users; --"},
		{"Unicode攻击", "＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ"},
	}

	for _, tc := range testCases {
		b.Run("Old_"+tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = sanitizeStringInput(tc.input)
			}
		})

		b.Run("New_"+tc.name, func(b *testing.B) {
			inferrer := &TypeInferrer{}
			processor := NewTypeAwareProcessor()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				paramType := inferrer.InferType(tc.input)
				_ = processor.ProcessString(tc.input, paramType)
			}
		})
	}
}

// BenchmarkTypeInference 测试类型推断性能
func BenchmarkTypeInference(b *testing.B) {
	inferrer := &TypeInferrer{}
	testCases := []string{
		"project_123_abc",
		"北京朝阳区项目",
		"这是一个很长的项目描述内容，包含多行文字说明和详细信息",
		"test' OR 1=1",
	}

	for _, input := range testCases {
		b.Run("InferType_"+input[:10], func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = inferrer.InferType(input)
			}
		})
	}
}

// BenchmarkValidators 测试各个验证器的性能
func BenchmarkValidators(b *testing.B) {
	validators := map[string]ParamValidator{
		"IDValidator":          IDValidator{},
		"NameValidator":        NameValidator{},
		"DescriptionValidator": DescriptionValidator{},
		"GenericValidator":     GenericValidator{},
	}

	testInputs := map[string]string{
		"Normal":    "正常输入内容",
		"Attack":    "'; DROP TABLE users; --",
		"Unicode":   "＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ",
		"LongText":  strings.Repeat("测试内容", 200),
	}

	for validatorName, validator := range validators {
		for inputName, input := range testInputs {
			b.Run(validatorName+"_"+inputName, func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = validator.Validate(input)
				}
			})
		}
	}
}

// BenchmarkLiteralFunction 测试literal函数性能
func BenchmarkLiteralFunction(b *testing.B) {
	testCases := []struct {
		name  string
		input interface{}
	}{
		{"String_Normal", "正常字符串"},
		{"String_Attack", "'; DROP TABLE users; --"},
		{"String_Unicode", "＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ"},
		{"Int", 123456},
		{"Bool", true},
		{"Nil", nil},
		{"ByteArray", []byte("test data")},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = literal(tc.input)
			}
		})
	}
}

// BenchmarkExpandFunction 测试Expand函数性能
func BenchmarkExpandFunction(b *testing.B) {
	testCases := []struct {
		name string
		sql  string
		vars []interface{}
	}{
		{
			name: "SimpleQuery",
			sql:  "SELECT * FROM users WHERE id = ?",
			vars: []interface{}{123},
		},
		{
			name: "MultipleParams",
			sql:  "SELECT * FROM projects WHERE name = ? AND city = ? AND status = ?",
			vars: []interface{}{"北京项目", "北京", 1},
		},
		{
			name: "AttackInput",
			sql:  "SELECT * FROM users WHERE name = ?",
			vars: []interface{}{"'; DROP TABLE users; --"},
		},
		{
			name: "UnicodeAttack",
			sql:  "SELECT * FROM projects WHERE name = ?",
			vars: []interface{}{"＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ"},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = Expand(tc.sql, tc.vars)
			}
		})
	}
}

// BenchmarkPatternMatching 测试模式匹配性能
func BenchmarkPatternMatching(b *testing.B) {
	input := "test'; DROP TABLE users; SELECT * FROM admin; --"
	
	b.Run("CaseInsensitiveReplace", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = replaceCaseInsensitive(input, "drop table", "drop_table")
		}
	})

	b.Run("StringsReplace", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = strings.ReplaceAll(input, "drop table", "drop_table")
		}
	})
}

// BenchmarkMemoryUsage 内存使用基准测试
func BenchmarkMemoryUsage(b *testing.B) {
	processor := NewTypeAwareProcessor()
	inferrer := &TypeInferrer{}
	
	longInput := strings.Repeat("这是一个包含中文和SQL注入'; DROP TABLE users; SELECT * FROM admin的长文本", 100)
	
	b.Run("ProcessLongString", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			paramType := inferrer.InferType(longInput)
			result := processor.ProcessString(longInput, paramType)
			_ = result // 防止编译器优化
		}
	})
}