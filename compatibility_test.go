package sqlhelper

import (
	"testing"
)

// TestBackwardCompatibility 测试向后兼容性，确保修复不会破坏现有功能
func TestBackwardCompatibility(t *testing.T) {
	// 测试现有功能的常见用例
	tests := []struct {
		name    string
		sql     string
		vars    []interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "项目查询-正常参数",
			sql:     "SELECT * FROM sync_erp_item WHERE project_id = ? ORDER BY parent_code ASC, CONVERT(proj_name USING GBK) ASC",
			vars:    []interface{}{"proj123"},
			want:    "SELECT * FROM sync_erp_item WHERE project_id = 'proj123' ORDER BY parent_code ASC, CONVERT(proj_name USING GBK) ASC",
			wantErr: false,
		},
		{
			name:    "用户查询-整数ID",
			sql:     "SELECT * FROM users WHERE id = ?",
			vars:    []interface{}{12345},
			want:    "SELECT * FROM users WHERE id = 12345",
			wantErr: false,
		},
		{
			name:    "时间范围查询",
			sql:     "SELECT * FROM logs WHERE created_at > ? AND status = ?",
			vars:    []interface{}{"2023-01-01 00:00:00", "active"},
			want:    "SELECT * FROM logs WHERE created_at > '2023-01-01 00:00:00' AND status = 'active'",
			wantErr: false,
		},
		{
			name:    "中文项目名称",
			sql:     "SELECT * FROM projects WHERE name = ?",
			vars:    []interface{}{"北京市朝阳区某某小区1期"},
			want:    "SELECT * FROM projects WHERE name = '北京市朝阳区某某小区1期'",
			wantErr: false,
		},
		{
			name:    "NULL值处理",
			sql:     "INSERT INTO table (col1, col2) VALUES (?, ?)",
			vars:    []interface{}{nil, "value"},
			want:    "INSERT INTO table (col1, col2) VALUES (NULL, 'value')",
			wantErr: false,
		},
		{
			name:    "布尔值处理",
			sql:     "UPDATE projects SET is_active = ?",
			vars:    []interface{}{true},
			want:    "UPDATE projects SET is_active = true",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.sql, tt.vars)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expand() 向后兼容性测试失败 - %s: error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Expand() 向后兼容性测试失败 - %s: got %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}