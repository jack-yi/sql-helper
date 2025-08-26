package sqlhelper

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParamType 参数类型枚举
type ParamType int

const (
	ParamTypeGeneric     ParamType = iota // 通用类型，默认处理
	ParamTypeID                           // ID类型：项目ID、用户ID等，严格验证
	ParamTypeName                         // 名称类型：项目名称、用户名等，中等验证
	ParamTypeDescription                  // 描述类型：详细描述、备注等，宽松验证
)

// ParamValidator 参数验证器接口
type ParamValidator interface {
	// Validate 验证并清理输入，返回清理后的安全字符串
	Validate(value string) string
	// GetType 返回验证器对应的参数类型
	GetType() ParamType
}

// IDValidator ID类型验证器，严格限制只允许字母数字短横线下划线
type IDValidator struct{}

func (v IDValidator) GetType() ParamType {
	return ParamTypeID
}

func (v IDValidator) Validate(value string) string {
	// 1. Unicode规范化，将全角字符转换为半角
	normalized := norm.NFKC.String(value)

	// 2. 只保留安全字符：字母、数字、短横线、下划线
	result := strings.Builder{}
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			result.WriteRune(r)
		} else {
			// 非法字符替换为下划线
			result.WriteRune('_')
		}
	}

	cleaned := result.String()

	// 3. 长度限制，防止过长输入
	if len(cleaned) > 100 {
		cleaned = cleaned[:100]
	}

	return cleaned
}

// DescriptionValidator 描述类型验证器，支持富文本内容，宽松验证
type DescriptionValidator struct{}

func (v DescriptionValidator) GetType() ParamType {
	return ParamTypeDescription
}

func (v DescriptionValidator) Validate(value string) string {
	// 1. Unicode规范化，将全角字符转换为半角
	normalized := norm.NFKC.String(value)

	// 2. 基本的空白符统一处理（保持格式，不合并多个空格）
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	// 3. 检测和替换危险SQL关键字模式（更少的限制，允许某些关键字在描述中存在）
	dangerousPatterns := map[string]string{
		// 只替换最危险的SQL注入模式
		"'; drop table":     "'; drop_table",
		"'; delete from":    "'; delete_from", 
		"'; truncate table": "'; truncate_table",
		"'; insert into":    "'; insert_into",
		"; drop table":      "; drop_table",
		"; delete from":     "; delete_from",
		"; truncate table":  "; truncate_table",
		"; insert into":     "; insert_into",
		"union select":      "union_select",
		"union all select":  "union_all_select",
		"xp_cmdshell":       "xp_cmd_shell",
		"sp_executesql":     "sp_execute_sql",
		// SQL注释在描述中可能是合法的，但仍然过滤连续的注释符号
		"--":                "_-",  // 单个减号替换为下划线减号
		"/*":                "/_*", // 注释开始
		"*/":                "*_/", // 注释结束
	}

	// 转为小写进行检测，但保持原始大小写进行替换
	lower := strings.ToLower(normalized)
	result := normalized

	for pattern, replacement := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			result = replaceCaseInsensitive(result, pattern, replacement)
			lower = strings.ToLower(result) // 更新小写版本用于下一次检查
		}
	}

	// 4. 长度限制（描述可以更长）
	if len(result) > 10000 {
		result = result[:10000]
	}

	return result
}

// GenericValidator 通用验证器，默认验证策略，平衡安全性和兼容性
type GenericValidator struct{}

func (v GenericValidator) GetType() ParamType {
	return ParamTypeGeneric
}

func (v GenericValidator) Validate(value string) string {
	// 1. Unicode规范化，将全角字符转换为半角
	normalized := norm.NFKC.String(value)

	// 2. 基本空白符处理
	normalized = strings.ReplaceAll(normalized, "\t", " ")
	normalized = strings.ReplaceAll(normalized, "\n", " ")
	normalized = strings.ReplaceAll(normalized, "\r", " ")
	// 合并多个连续空格为单个空格
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	normalized = strings.TrimSpace(normalized)

	// 3. 检测和替换常见SQL注入关键字模式
	dangerousPatterns := map[string]string{
		"union select":      "union_select",
		"union all select":  "union_all_select",
		"'; drop table":     "'; drop_table",
		"'; delete from":    "'; delete_from",
		"'; truncate table": "'; truncate_table",
		"'; insert into":    "'; insert_into",
		"'; update ":        "'; update_",
		"; drop table":      "; drop_table",
		"; delete from":     "; delete_from",
		"; truncate table":  "; truncate_table", 
		"; insert into":     "; insert_into",
		"; update ":         "; update_",
		" or 1=1":           "_or_1=1",
		" or '1'='1":        "_or_'1'='1",
		" and 1=1":          "_and_1=1",
		"/*":                "/_*",
		"*/":                "*_/",
		"--":                "__",
		"xp_cmdshell":       "xp_cmd_shell",
		"sp_executesql":     "sp_execute_sql",
	}

	// 转为小写进行检测，但保持原始大小写进行替换
	lower := strings.ToLower(normalized)
	result := normalized

	for pattern, replacement := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			result = replaceCaseInsensitive(result, pattern, replacement)
			lower = strings.ToLower(result) // 更新小写版本用于下一次检查
		}
	}

	// 4. 长度限制
	if len(result) > 2000 {
		result = result[:2000]
	}

	return result
}

// NameValidator 名称类型验证器，支持中文，检测SQL注入关键字
type NameValidator struct{}

func (v NameValidator) GetType() ParamType {
	return ParamTypeName
}

func (v NameValidator) Validate(value string) string {
	// 1. Unicode规范化，将全角字符转换为半角
	normalized := norm.NFKC.String(value)

	// 2. 统一空白符处理
	normalized = strings.ReplaceAll(normalized, "\t", " ")
	normalized = strings.ReplaceAll(normalized, "\n", " ")
	normalized = strings.ReplaceAll(normalized, "\r", " ")
	// 合并多个连续空格为单个空格
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	normalized = strings.TrimSpace(normalized)

	// 3. 检测和替换危险SQL关键字模式
	dangerousPatterns := map[string]string{
		"union select":     "union_select",
		"union all select": "union_all_select",
		" or ":             "_or_",
		" and ":            "_and_",
		"' or '":           "'_or_'",
		"\" or \"":         "\"_or_\"",
		"' and '":          "'_and_'",
		"\" and \"":        "\"_and_\"",
		" or 1=1":          "_or_1=1",
		" or '1'='1":       "_or_'1'='1",
		"'; drop table":    "'; drop_table",
		"'; delete from":   "'; delete_from",
		"'; insert into":   "'; insert_into",
		"'; update set":    "'; update_set",
		"/*":               "/_*",
		"*/":               "*_/",
		"--":               "__",
		"#":                "_#",
		"xp_cmdshell":      "xp_cmd_shell",
		"sp_executesql":    "sp_execute_sql",
		"ascii":            "_ascii_",
		"substring":        "_substring_",
		"concat":           "_concat_",
		"extractvalue":     "_extractvalue_",
		"waitfor":          "_waitfor_",
		"delay":            "_delay_",
	}

	// 转为小写进行检测，但保持原始大小写进行替换
	lower := strings.ToLower(normalized)
	result := normalized

	for pattern, replacement := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			result = replaceCaseInsensitive(result, pattern, replacement)
			lower = strings.ToLower(result) // 更新小写版本用于下一次检查
		}
	}

	// 4. 长度限制
	if len(result) > 500 {
		result = result[:500]
	}

	return result
}

// TypeAwareProcessor 类型感知处理器管理器
type TypeAwareProcessor struct {
	validators map[ParamType]ParamValidator
}

// NewTypeAwareProcessor 创建类型感知处理器
func NewTypeAwareProcessor() *TypeAwareProcessor {
	processor := &TypeAwareProcessor{
		validators: make(map[ParamType]ParamValidator),
	}
	
	// 注册所有验证器
	processor.RegisterValidator(IDValidator{})
	processor.RegisterValidator(NameValidator{})
	processor.RegisterValidator(DescriptionValidator{})
	processor.RegisterValidator(GenericValidator{})
	
	return processor
}

// RegisterValidator 注册验证器
func (tap *TypeAwareProcessor) RegisterValidator(validator ParamValidator) {
	tap.validators[validator.GetType()] = validator
}

// GetValidator 获取指定类型的验证器
func (tap *TypeAwareProcessor) GetValidator(paramType ParamType) ParamValidator {
	if validator, exists := tap.validators[paramType]; exists {
		return validator
	}
	// 默认返回通用验证器
	return tap.validators[ParamTypeGeneric]
}

// ProcessString 处理字符串参数，使用指定类型的验证器
func (tap *TypeAwareProcessor) ProcessString(value string, paramType ParamType) string {
	validator := tap.GetValidator(paramType)
	return validator.Validate(value)
}

// 全局类型感知处理器实例
var globalProcessor = NewTypeAwareProcessor()

// TypeInferrer 类型推断器，根据字符串内容推断参数类型
type TypeInferrer struct{}

// InferType 推断参数类型
func (ti *TypeInferrer) InferType(value string) ParamType {
	// 长度检查优先级最高
	if len(value) == 0 {
		return ParamTypeGeneric
	}

	// ID类型检测：纯字母数字组合，通常较短
	if len(value) <= 100 {
		isID := true
		for _, r := range value {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
			     (r >= '0' && r <= '9') || r == '-' || r == '_') {
				isID = false
				break
			}
		}
		if isID {
			return ParamTypeID
		}
	}

	// 描述类型检测：长度超过500或包含换行符
	if len(value) > 500 || strings.Contains(value, "\n") || strings.Contains(value, "\r") {
		return ParamTypeDescription
	}

	// 名称类型检测：包含中文字符或常见名称模式
	hasChineseOrNamePattern := false
	for _, r := range value {
		// 检测中文字符范围
		if (r >= 0x4e00 && r <= 0x9fff) || // 中文基本汉字
		   (r >= 0x3400 && r <= 0x4dbf) || // 中文扩展A
		   (r >= 0xf900 && r <= 0xfaff) {  // 中文兼容汉字
			hasChineseOrNamePattern = true
			break
		}
	}
	
	// 检测常见名称模式
	if !hasChineseOrNamePattern {
		namePatterns := []string{"项目", "小区", "大厦", "广场", "中心", "花园", "公寓", "别墅", "期", "区", "号"}
		for _, pattern := range namePatterns {
			if strings.Contains(value, pattern) {
				hasChineseOrNamePattern = true
				break
			}
		}
	}
	
	if hasChineseOrNamePattern {
		return ParamTypeName
	}

	// 默认返回通用类型
	return ParamTypeGeneric
}

// 全局类型推断器实例
var globalInferrer = &TypeInferrer{}

// Expand 把带 ? 占位符的 SQL 展开成可直接执行的纯文本 SQL
// 如果占位符数量与参数个数不符，或出现未知类型，返回 error
func Expand(sql string, vars []interface{}) (string, error) {
	var (
		buf   strings.Builder
		argI  = 0
		start int
	)
	for pos := strings.IndexByte(sql[start:], '?'); pos >= 0; pos = strings.IndexByte(sql[start:], '?') {
		if argI >= len(vars) {
			return "", errors.New("占位符个数 > 参数个数")
		}
		pos += start
		buf.WriteString(sql[:pos])      // 复制到 ? 之前
		lit, err := literal(vars[argI]) // 转义值
		if err != nil {
			return "", err
		}
		buf.WriteString(lit)
		sql = sql[pos+1:] // 去掉已处理部分
		start = 0
		argI++
	}
	if argI != len(vars) {
		return "", errors.New("占位符个数 < 参数个数")
	}
	buf.WriteString(sql)
	return buf.String(), nil
}

// Literal 把 Go 值转成 SQL 字面量（导出版本用于测试）
func Literal(v interface{}) (string, error) {
	return literal(v)
}

// literal 把 Go 值转成 SQL 字面量
func literal(v interface{}) (string, error) {
	switch val := v.(type) {
	case nil:
		return "NULL", nil
	case bool:
		return strconv.FormatBool(val), nil
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val), nil
	case float32, float64:
		return strconv.FormatFloat(
			reflectFloat(val), 'g', -1, 64), nil
	case string:
		// 使用类型感知验证进行字符串清理
		paramType := globalInferrer.InferType(val)
		sanitized := globalProcessor.ProcessString(val, paramType)
		return quoteString(sanitized), nil
	case []byte:
		str := string(val)
		// 使用类型感知验证进行字符串清理
		paramType := globalInferrer.InferType(str)
		sanitized := globalProcessor.ProcessString(str, paramType)
		return quoteString(sanitized), nil
	case time.Time:
		return fmt.Sprintf("'%s'", val.Format("2006-01-02 15:04:05")), nil
	default:
		// 处理 driver.Valuer
		if vv, ok := val.(driver.Valuer); ok {
			dv, err := vv.Value()
			if err != nil {
				return "", err
			}
			return literal(dv)
		}
		return "", fmt.Errorf("unsupported type %T", val)
	}
}

func reflectFloat(v interface{}) float64 {
	switch v := v.(type) {
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		panic("not float")
	}
}

// sanitizeStringInput 清理字符串输入，移除或替换潜在的SQL注入攻击模式
func sanitizeStringInput(s string) string {
	// 检查字符串长度，截断过长的输入
	if len(s) > 65535 { // MySQL TEXT字段的最大长度
		s = s[:65535]
	}

	// 检测并替换常见的SQL注入关键字组合
	dangerousPatterns := map[string]string{
		"union select":     "union_select",
		"union all select": "union_all_select",
		"' or '1'='1":      "'_or_'1'='1",
		"' or 1=1":         "'_or_1=1",
		"'; drop table":    "';_drop_table",
		"'; delete from":   "';_delete_from",
		"'; update ":       "';_update_",
		"'; insert into":   "';_insert_into",
		"/*":               "/_*",
		"*/":               "*_/",
		"--":               "__",
		"xp_cmdshell":      "xp_cmd_shell",
		"sp_executesql":    "sp_execute_sql",
	}

	// 将字符串转换为小写进行匹配，但保持原始大小写进行替换
	lower := strings.ToLower(s)
	result := s

	for pattern, replacement := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			// 使用大小写不敏感的替换
			result = replaceCaseInsensitive(result, pattern, replacement)
			lower = strings.ToLower(result) // 更新小写版本用于下一次检查
		}
	}

	return result
}

// replaceCaseInsensitive 执行大小写不敏感的字符串替换
func replaceCaseInsensitive(s, old, new string) string {
	// 使用正则表达式进行大小写不敏感替换
	oldLower := strings.ToLower(old)
	sLower := strings.ToLower(s)

	// 找到所有匹配位置
	var result strings.Builder
	lastEnd := 0

	for {
		index := strings.Index(sLower[lastEnd:], oldLower)
		if index == -1 {
			break
		}

		// 添加匹配前的部分
		actualIndex := lastEnd + index
		result.WriteString(s[lastEnd:actualIndex])

		// 添加替换字符串
		result.WriteString(new)

		// 更新位置
		lastEnd = actualIndex + len(old)
	}

	// 添加剩余部分
	result.WriteString(s[lastEnd:])

	return result.String()
}

func quoteString(s string) string {
	// 转义所有可能导致SQL注入的特殊字符
	s = strings.ReplaceAll(s, "\\", "\\\\")  // 反斜杠必须首先转义
	s = strings.ReplaceAll(s, "'", "''")     // 单引号转义
	s = strings.ReplaceAll(s, "\"", "\\\"")  // 双引号转义
	s = strings.ReplaceAll(s, "\n", "\\n")   // 换行符转义
	s = strings.ReplaceAll(s, "\r", "\\r")   // 回车符转义
	s = strings.ReplaceAll(s, "\t", "\\t")   // 制表符转义
	s = strings.ReplaceAll(s, "\x00", "\\0") // 空字节转义
	s = strings.ReplaceAll(s, "\x1a", "\\Z") // Control-Z转义
	return "'" + s + "'"
}
