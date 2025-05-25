from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import re

app = Flask(__name__)
app.secret_key = 'fa0b99db8db1d3b9ad179615c41a170b'  # 用于闪现消息
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    callsign = db.Column(db.String(20), nullable=False)

# 日志模型
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    callsign = db.Column(db.String(20), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(8), nullable=False)
    frequency = db.Column(db.Float, nullable=False)
    mode = db.Column(db.String(20), nullable=False)
    rst_sent = db.Column(db.String(10))
    rst_received = db.Column(db.String(10))
    remarks = db.Column(db.Text)

# 创建uploads目录（如果不存在）
os.makedirs('uploads', exist_ok=True)

# 首页
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # 添加新日志
        new_log = LogEntry(
            user_id=session['user_id'],
            callsign=request.form['callsign'],
            date=request.form['date'],
            time=request.form['time'],
            frequency=float(request.form['frequency']),
            mode=request.form['mode'],
            rst_sent=request.form.get('rst_sent'),
            rst_received=request.form.get('rst_received'),
            remarks=request.form.get('remarks')
        )
        
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('index'))
    
    # 获取用户所有日志
    logs = LogEntry.query.filter_by(user_id=session['user_id']).all()
    return render_template('index.html', logs=logs, username=user.username)

# 注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        callsign = request.form['callsign']
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='用户名已存在')
        
        new_user = User(
            username=username,
            password_hash=password,  # 注意：实际项目中应使用哈希加密
            callsign=callsign
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password_hash == password:  # 注意：实际项目中应使用哈希验证
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

# 退出
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# 删除日志
@app.route('/delete_log/<int:id>')
def delete_log(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    log = LogEntry.query.get_or_404(id)
    
    if log.user_id == session['user_id']:
        db.session.delete(log)
        db.session.commit()
    
    return redirect(url_for('index'))

# ADIF导出功能
@app.route('/export_adif')
def export_adif():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    logs = LogEntry.query.filter_by(user_id=session['user_id']).all()
    
    # 构建ADIF内容
    adif_content = '<ADIF_VER:5>3.0.0\n<EOH>\n'
    
    for log in logs:
        # 添加日志字段
        adif_content += f'<CALL:{len(log.callsign)}>{log.callsign}'
        adif_content += f'<QSO_DATE:8>{log.date.replace("-", "")}'
        adif_content += f'<TIME_ON:6>{log.time.replace(":", "")}'
        adif_content += f'<FREQ:{len(str(log.frequency))}>{log.frequency}'
        adif_content += f'<MODE:{len(log.mode)}>{log.mode}'
        
        if log.rst_sent:
            adif_content += f'<RST_SENT:{len(log.rst_sent)}>{log.rst_sent}'
        if log.rst_received:
            adif_content += f'<RST_RCVD:{len(log.rst_received)}>{log.rst_received}'
        if log.remarks:
            adif_content += f'<COMMENT:{len(log.remarks)}>{log.remarks}'
        
        adif_content += '<EOR>\n'  # 记录结束
    
    # 保存并发送文件
    with open('temp_adif.adi', 'w', encoding='utf-8') as f:
        f.write(adif_content)
    
    return send_file(
        'temp_adif.adi',
        as_attachment=True,
        download_name='qso_logs.adi',
        mimetype='text/plain'
    )

# ADIF导入功能
@app.route('/import_adif', methods=['POST'])
def import_adif():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'adif_file' not in request.files:
        flash('未选择文件', 'error')
        return redirect(url_for('index'))
    
    file = request.files['adif_file']
    if file.filename == '':
        flash('文件名不能为空', 'error')
        return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    file_path = os.path.join('uploads', filename)
    file.save(file_path)
    
    try:
        # 读取文件并记录详细调试信息
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()
        
        # 详细调试信息
        print(f"ADIF文件内容长度: {len(content)}")
        print(f"文件前100个字符: {repr(content[:100])}")
        print(f"文件后100个字符: {repr(content[-100:])}")
        
        # 更宽容的ADIF内容清理
        content = re.sub(r'<--.*?$', '', content, flags=re.M)  # 移除注释
        content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)  # 移除控制字符
        
        # 保留换行符，但合并连续空格
        content = re.sub(r'[ \t]+', ' ', content)
        content = content.strip()
        
        # 调试：输出清理后的内容
        print(f"清理后的内容长度: {len(content)}")
        
        # 更灵活的ADIF标签解析器
        records = []
        current_record = {}
        in_header = True
        eoh_found = False  # 跟踪是否找到EOH标记
        
        # 正则表达式匹配ADIF标签（更灵活的匹配）
        tag_pattern = re.compile(r'<\s*([A-Z0-9_]+)\s*:\s*(\d+)\s*(?::\s*([A-Z0-9]+)\s*)?>([^<]*)')
        
        # 记录解析过程中的问题
        parse_errors = []
        
        # 调试：在解析前检查内容中是否存在EOH字符串
        if '<EOH>' in content:
            print("内容中存在字符串 '<EOH>'")
        else:
            print("内容中未找到字符串 '<EOH>'")
        
        # 调试：查找所有类似EOH的标签
        potential_eoh_tags = re.findall(r'<\s*EOH\s*[^>]*>', content, re.IGNORECASE)
        if potential_eoh_tags:
            print("找到潜在的EOH标签:")
            for tag in potential_eoh_tags:
                print(f"  - {repr(tag)}")
        else:
            print("未找到潜在的EOH标签")
        
        for match in tag_pattern.finditer(content):
            if not match:
                parse_errors.append(f"无法解析的内容: {content[:50]}...")
                continue
                
            field = match.group(1).strip()
            try:
                length = int(match.group(2).strip())
            except ValueError:
                parse_errors.append(f"无效的长度值: {match.group(2)}")
                continue
                
            value_type = match.group(3)  # 类型信息，可选
            value = match.group(4).strip()
            
            # 调试：输出每个解析的标签及其上下文
            print(f"解析标签: <{field}:{length}{':'+value_type if value_type else ''}>{value} (in_header={in_header})")
            
            # 检查是否是头部结束标记
            if field.upper() == 'EOH':
                # 验证EOH标签格式是否正确
                eoh_tag = match.group(0)
                print(f"找到疑似EOH标签: {repr(eoh_tag)}")
                
                # 标准EOH标签应该是<EOH:0>或<EOH>
                if not re.match(r'<\s*EOH\s*(?::\s*0\s*)?>', eoh_tag, re.IGNORECASE):
                    parse_errors.append(f"无效的EOH标签格式: {eoh_tag}")
                    print(f"警告: 无效的EOH标签格式: {eoh_tag}")
                else:
                    in_header = False
                    eoh_found = True
                    print("找到有效EOH标记，开始解析记录")
                continue
                
            if in_header:
                print(f"跳过头部标签: {field}")
                continue
                
            # 验证值长度
            if len(value) != length:
                parse_errors.append(f"字段 {field} 声明长度 {length} 与实际长度 {len(value)} 不符")
                # 不再截断值，使用原始值
                # value = value[:length]
                
            # 处理特殊字段
            if field.upper() == 'EOR':
                if current_record:
                    records.append(current_record)
                    print(f"成功解析一条记录: {current_record.get('CALL', '未知呼号')}")
                    current_record = {}
                else:
                    parse_errors.append("空的EOR标记，没有对应的记录数据")
                continue
                
            current_record[field] = value
        
        # 调试：输出解析结果
        print(f"共解析出 {len(records)} 条记录")
        print(f"是否找到EOH标记: {eoh_found}")
        print(f"解析错误: {parse_errors}")
        
        # 导入记录到数据库
        imported_count = 0
        skipped_records = []
        
        for i, record in enumerate(records):
            errors = []
            
            # 验证必需字段
            if 'CALL' not in record:
                errors.append("缺少呼号(CALL)字段")
            if 'QSO_DATE' not in record:
                errors.append("缺少日期(QSO_DATE)字段")
            if 'TIME_ON' not in record:
                errors.append("缺少时间(TIME_ON)字段")
                
            if errors:
                skipped_records.append({
                    'index': i + 1,
                    'call': record.get('CALL', '未知'),
                    'errors': errors
                })
                continue
                
            # 格式化日期
            date_str = record['QSO_DATE']
            formatted_date = None
            
            if len(date_str) == 10 and '-' in date_str:  # YYYY-MM-DD
                formatted_date = date_str
            elif len(date_str) == 8:  # YYYYMMDD
                formatted_date = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"
            else:
                errors.append(f"无效日期格式: {date_str} (应为YYYYMMDD或YYYY-MM-DD)")
                
            # 格式化时间
            time_str = record['TIME_ON']
            formatted_time = None
            
            if len(time_str) == 8 and ':' in time_str:  # HH:MM:SS
                formatted_time = time_str
            elif len(time_str) == 5 and ':' in time_str:  # HH:MM
                formatted_time = f"{time_str}:00"
            elif len(time_str) == 6:  # HHMMSS
                formatted_time = f"{time_str[:2]}:{time_str[2:4]}:{time_str[4:]}"
            elif len(time_str) == 4:  # HHMM
                formatted_time = f"{time_str[:2]}:{time_str[2:4]}:00"
            else:
                errors.append(f"无效时间格式: {time_str} (应为HHMMSS、HHMM、HH:MM:SS或HH:MM)")
                
            # 处理频率
            freq_str = record.get('FREQ', '0')
            try:
                frequency = float(freq_str)
            except ValueError:
                frequency = 0.0
                errors.append(f"无效频率值: {freq_str}")
                
            # 检查是否有错误
            if errors:
                skipped_records.append({
                    'index': i + 1,
                    'call': record.get('CALL', '未知'),
                    'errors': errors
                })
                continue
                
            # 创建新日志条目
            new_log = LogEntry(
                user_id=session['user_id'],
                callsign=record['CALL'],
                date=formatted_date,
                time=formatted_time,
                frequency=frequency,
                mode=record.get('MODE', ''),
                rst_sent=record.get('RST_SENT', ''),
                rst_received=record.get('RST_RCVD', ''),
                remarks=record.get('COMMENT', '')
            )
            
            db.session.add(new_log)
            imported_count += 1
        
        if imported_count > 0:
            db.session.commit()
            
            if skipped_records or parse_errors:
                error_message = f'成功导入 {imported_count} 条日志'
                
                if parse_errors:
                    error_message += f'<br><br>解析警告:<br><ul><li>'
                    error_message += '</li><li>'.join(parse_errors)
                    error_message += '</ul>'
                    
                if skipped_records:
                    error_message += f'<br><br>跳过 {len(skipped_records)} 条无效记录:<br><ul>'
                    for record in skipped_records:
                        error_message += f'<li>记录 #{record["index"]} ({record["call"]}): {", ".join(record["errors"])}</li>'
                    error_message += '</ul>'
                    
                flash(error_message, 'error')
            else:
                flash(f'成功导入 {imported_count} 条日志', 'success')
        else:
            error_message = '未导入任何日志，ADIF文件可能为空或所有记录均无效<br><br>'
            
            if not eoh_found:
                error_message += '<p>解析器未找到有效的EOH标记，请确保ADIF文件格式正确。</p>'
                
            if parse_errors:
                error_message += f'解析错误:<br><ul><li>'
                error_message += '</li><li>'.join(parse_errors)
                error_message += '</ul>'
                
            if skipped_records:
                error_message += f'<br><br>跳过 {len(skipped_records)} 条无效记录:<br><ul>'
                for record in skipped_records:
                    error_message += f'<li>记录 #{record["index"]} ({record["call"]}): {", ".join(record["errors"])}</li>'
                error_message += '</ul>'
                
            flash(error_message, 'error')
            
        return redirect(url_for('index'))
        
    except Exception as e:
        flash(f"导入失败: {str(e)}", 'error')
        print(f"导入异常: {str(e)}")
        return redirect(url_for('index'))
    finally:
        os.remove(file_path)  # 删除临时文件

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 创建数据库表
    app.run(debug=True)