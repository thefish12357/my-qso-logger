import os
import fnmatch
from pathlib import Path

def load_gitignore(path='.gitignore'):
    """加载.gitignore规则"""
    if not os.path.exists(path):
        return []
    
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def is_ignored(file_path, gitignore_rules, base_dir=''):
    """检查文件是否应被忽略"""
    # 规范化路径
    file_path = os.path.relpath(file_path, base_dir)
    
    # 检查绝对路径匹配
    for rule in gitignore_rules:
        if rule.startswith('/'):
            # 绝对路径规则
            if fnmatch.fnmatch(file_path, rule[1:]):
                return True
        else:
            # 相对路径规则
            if fnmatch.fnmatch(file_path, rule):
                return True
    
    return False

def scan_project(root_dir='.', show_ignored=False):
    """扫描项目目录，返回待上传和已忽略的文件列表"""
    gitignore_rules = load_gitignore()
    
    upload_files = []
    ignored_files = []
    
    for root, dirs, files in os.walk(root_dir):
        # 跳过.git目录
        if '.git' in root:
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            if is_ignored(file_path, gitignore_rules, root_dir):
                ignored_files.append(file_path)
            else:
                upload_files.append(file_path)
    
    return upload_files, ignored_files

def main():
    """主函数：显示扫描结果"""
    print("正在扫描项目目录...")
    upload_files, ignored_files = scan_project()
    
    print("\n需要上传的文件:")
    for file in upload_files:
        print(f"- {file}")
    
    print(f"\n总计: {len(upload_files)} 个文件需要上传")
    
    print("\n已忽略的文件:")
    for file in ignored_files[:10]:  # 只显示前10个，避免过多
        print(f"- {file}")
    if len(ignored_files) > 10:
        print(f"- ... 等 {len(ignored_files) - 10} 个文件")
    
    print(f"\n总计: {len(ignored_files)} 个文件被忽略")

if __name__ == "__main__":
    main()