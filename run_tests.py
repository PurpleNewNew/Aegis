#!/usr/bin/env python3
"""
运行所有被动模式测试
"""
import sys
import os
import subprocess

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def run_passive_mode_tests():
    """运行被动模式的所有测试"""
    print("=== 运行被动模式交互复现测试 ===\n")
    
    # 运行交互测试
    test_path = os.path.join(project_root, 'tests', 'passive_mode', 'test_passive_mode_interaction.py')
    
    try:
        result = subprocess.run([sys.executable, test_path], 
                              capture_output=True, 
                              text=True,
                              cwd=project_root)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
            
        print(f"\n测试完成，返回码: {result.returncode}")
        
    except Exception as e:
        print(f"运行测试时出错: {e}")

if __name__ == "__main__":
    run_passive_mode_tests()