package sqlhelper

import (
	"strings"
	"testing"
)

// TestParamValidators 测试各个参数验证器
func TestParamValidators(t *testing.T) {
	tests := []struct {
		name      string
		validator ParamValidator
		input     string
		expected  string
	}{
		// IDValidator 测试
		{
			name:      "IDValidator - 正常ID",
			validator: IDValidator{},
			input:     "project_123_abc",
			expected:  "project_123_abc",
		},
		{
			name:      "IDValidator - 包含非法字符",
			validator: IDValidator{},
			input:     "project@123#abc",
			expected:  "project_123_abc",
		},
		{
			name:      "IDValidator - Unicode字符转换",
			validator: IDValidator{},
			input:     "ｐｒｏｊｅｃｔ１２３",
			expected:  "project123",
		},
		
		// NameValidator 测试
		{
			name:      "NameValidator - 正常中文名称",
			validator: NameValidator{},
			input:     "北京朝阳区项目",
			expected:  "北京朝阳区项目",
		},
		{
			name:      "NameValidator - 包含SQL注入",
			validator: NameValidator{},
			input:     "项目'; DROP TABLE users--",
			expected:  "项目'; drop_table users__",
		},
		{
			name:      "NameValidator - 大小写混合攻击",
			validator: NameValidator{},
			input:     "项目' UnIoN sElEcT * FROM users",
			expected:  "项目' union_select * FROM users",
		},

		// DescriptionValidator 测试
		{
			name:      "DescriptionValidator - 正常描述",
			validator: DescriptionValidator{},
			input:     "这是一个位于市中心的高档住宅项目\n配套设施齐全",
			expected:  "这是一个位于市中心的高档住宅项目\n配套设施齐全",
		},
		{
			name:      "DescriptionValidator - 包含危险SQL",
			validator: DescriptionValidator{},
			input:     "项目描述'; DROP TABLE users; --",
			expected:  "项目描述'; drop_table users; _-",
		},

		// GenericValidator 测试
		{
			name:      "GenericValidator - 正常文本",
			validator: GenericValidator{},
			input:     "测试文本内容",
			expected:  "测试文本内容",
		},
		{
			name:      "GenericValidator - 包含SQL注入",
			validator: GenericValidator{},
			input:     "test' OR 1=1--",
			expected:  "test'_or_1=1__",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.validator.Validate(tt.input)
			if result != tt.expected {
				t.Errorf("%s.Validate(%q) = %q, want %q", tt.name, tt.input, result, tt.expected)
			}
		})
	}
}

// TestTypeInferrer 测试类型推断器
func TestTypeInferrer(t *testing.T) {
	inferrer := &TypeInferrer{}
	
	tests := []struct {
		name     string
		input    string
		expected ParamType
	}{
		{
			name:     "推断ID类型",
			input:    "project_123_abc",
			expected: ParamTypeID,
		},
		{
			name:     "推断名称类型 - 中文",
			input:    "北京朝阳区项目",
			expected: ParamTypeName,
		},
		{
			name:     "推断名称类型 - 包含项目关键字",
			input:    "某某小区1期",
			expected: ParamTypeName,
		},
		{
			name:     "推断描述类型 - 长文本",
			input:    strings.Repeat("这是一个很长的描述内容", 50),
			expected: ParamTypeDescription,
		},
		{
			name:     "推断描述类型 - 包含换行",
			input:    "项目描述\n第二行内容",
			expected: ParamTypeDescription,
		},
		{
			name:     "推断通用类型",
			input:    "general text content",
			expected: ParamTypeGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferrer.InferType(tt.input)
			if result != tt.expected {
				t.Errorf("InferType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestTypeAwareProcessor 测试类型感知处理器
func TestTypeAwareProcessor(t *testing.T) {
	processor := NewTypeAwareProcessor()
	
	tests := []struct {
		name      string
		input     string
		paramType ParamType
		expected  string
	}{
		{
			name:      "处理ID类型",
			input:     "project@123",
			paramType: ParamTypeID,
			expected:  "project_123",
		},
		{
			name:      "处理名称类型",
			input:     "项目'; DROP TABLE users",
			paramType: ParamTypeName,
			expected:  "项目'; drop_table users",
		},
		{
			name:      "处理描述类型",
			input:     "描述内容'; DROP TABLE users; --",
			paramType: ParamTypeDescription,
			expected:  "描述内容'; drop_table users; _-",
		},
		{
			name:      "处理通用类型",
			input:     "test' OR 1=1",
			paramType: ParamTypeGeneric,
			expected:  "test'_or_1=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.ProcessString(tt.input, tt.paramType)
			if result != tt.expected {
				t.Errorf("ProcessString(%q, %v) = %q, want %q", tt.input, tt.paramType, result, tt.expected)
			}
		})
	}
}

// TestTypeAwareLiteral 测试集成类型感知的literal函数
func TestTypeAwareLiteral(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "ID类型自动识别",
			input:    "project_123_abc",
			expected: "'project_123_abc'",
		},
		{
			name:     "名称类型自动识别和处理",
			input:    "北京项目'; DROP TABLE users",
			expected: "'北京项目''; drop_table users'",
		},
		{
			name:     "描述类型自动识别",
			input:    "这是一个很长的项目描述内容\n包含多行文字说明",
			expected: "'这是一个很长的项目描述内容\\n包含多行文字说明'",
		},
		{
			name:     "Unicode攻击自动处理",
			input:    "＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ",
			expected: "''' union_select'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := literal(tt.input)
			if err != nil {
				t.Errorf("literal(%v) error = %v", tt.input, err)
				return
			}
			if result != tt.expected {
				t.Errorf("literal(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestQuoteString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "正常字符串",
			input:    "hello world",
			expected: "'hello world'",
		},
		{
			name:     "包含单引号",
			input:    "hello's world",
			expected: "'hello''s world'",
		},
		{
			name:     "包含反斜杠",
			input:    "hello\\world",
			expected: "'hello\\\\world'",
		},
		{
			name:     "包含双引号",
			input:    `hello"world`,
			expected: `'hello\"world'`,
		},
		{
			name:     "包含换行符",
			input:    "hello\nworld",
			expected: "'hello\\nworld'",
		},
		{
			name:     "包含制表符",
			input:    "hello\tworld",
			expected: "'hello\\tworld'",
		},
		{
			name:     "包含回车符",
			input:    "hello\rworld",
			expected: "'hello\\rworld'",
		},
		{
			name:     "包含空字节",
			input:    "hello\x00world",
			expected: "'hello\\0world'",
		},
		{
			name:     "包含Control-Z",
			input:    "hello\x1aworld",
			expected: "'hello\\Zworld'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := quoteString(tt.input)
			if result != tt.expected {
				t.Errorf("quoteString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeStringInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "正常字符串",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "包含UNION SELECT攻击",
			input:    "'; UNION SELECT * FROM users--",
			expected: "'; union_select * FROM users__",
		},
		{
			name:     "包含UNION ALL SELECT攻击",
			input:    "test' UNION ALL SELECT password FROM admin",
			expected: "test' union_all_select password FROM admin",
		},
		{
			name:     "包含OR 1=1攻击",
			input:    "admin' OR 1=1--",
			expected: "admin'_or_1=1__",
		},
		{
			name:     "包含DROP TABLE攻击",
			input:    "'; DROP TABLE users;--",
			expected: "';_drop_table users;__",
		},
		{
			name:     "包含DELETE FROM攻击",
			input:    "'; DELETE FROM users;--",
			expected: "';_delete_from users;__",
		},
		{
			name:     "包含SQL注释",
			input:    "test/*comment*/",
			expected: "test/_*comment*_/",
		},
		{
			name:     "包含SQL注释--",
			input:    "test--comment",
			expected: "test__comment",
		},
		{
			name:     "包含xp_cmdshell",
			input:    "'; exec xp_cmdshell('dir');--",
			expected: "'; exec xp_cmd_shell('dir');__",
		},
		{
			name:     "大小写混合的攻击",
			input:    "'; UnIoN sElEcT * FROM users--",
			expected: "'; union_select * FROM users__",
		},
		{
			name:     "正常的项目名称",
			input:    "北京市朝阳区某某小区1期",
			expected: "北京市朝阳区某某小区1期",
		},
		{
			name:     "过长字符串会被截断",
			input:    strings.Repeat("a", 70000),
			expected: strings.Repeat("a", 65535),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeStringInput(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeStringInput(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLiteral(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "nil值",
			input:   nil,
			want:    "NULL",
			wantErr: false,
		},
		{
			name:    "布尔值true",
			input:   true,
			want:    "true",
			wantErr: false,
		},
		{
			name:    "布尔值false",
			input:   false,
			want:    "false",
			wantErr: false,
		},
		{
			name:    "整数",
			input:   123,
			want:    "123",
			wantErr: false,
		},
		{
			name:    "浮点数",
			input:   123.45,
			want:    "123.45",
			wantErr: false,
		},
		{
			name:    "正常字符串",
			input:   "hello",
			want:    "'hello'",
			wantErr: false,
		},
		{
			name:    "包含SQL注入的字符串会被清理",
			input:   "'; DROP TABLE users;--",
			want:    "'''; drop_table users;__'",
			wantErr: false,
		},
		{
			name:    "字节数组",
			input:   []byte("hello"),
			want:    "'hello'",
			wantErr: false,
		},
		{
			name:    "包含SQL注入的字节数组会被清理",
			input:   []byte("'; UNION SELECT * FROM users--"),
			want:    "'''; union_select * FROM users__'",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := literal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("literal(%v) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("literal(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		vars    []interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "正常查询",
			sql:     "SELECT * FROM users WHERE id = ?",
			vars:    []interface{}{123},
			want:    "SELECT * FROM users WHERE id = 123",
			wantErr: false,
		},
		{
			name:    "多个参数",
			sql:     "SELECT * FROM users WHERE id = ? AND name = ?",
			vars:    []interface{}{123, "john"},
			want:    "SELECT * FROM users WHERE id = 123 AND name = 'john'",
			wantErr: false,
		},
		{
			name:    "包含SQL注入的参数会被清理",
			sql:     "SELECT * FROM users WHERE name = ?",
			vars:    []interface{}{"'; DROP TABLE users;--"},
			want:    "SELECT * FROM users WHERE name = '''; drop_table users;__'",
			wantErr: false,
		},
		{
			name:    "占位符数量不匹配-参数过多",
			sql:     "SELECT * FROM users WHERE id = ?",
			vars:    []interface{}{123, "extra"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "占位符数量不匹配-参数过少",
			sql:     "SELECT * FROM users WHERE id = ? AND name = ?",
			vars:    []interface{}{123},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.sql, tt.vars)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expand(%q, %v) error = %v, wantErr %v", tt.sql, tt.vars, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Expand(%q, %v) = %q, want %q", tt.sql, tt.vars, got, tt.want)
			}
		})
	}
}