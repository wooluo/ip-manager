from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import ipaddress
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ip_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 数据库模型定义
class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

class WhitelistIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), unique=True, nullable=False)

class UnblockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), unique=True, nullable=False)
    unblocked_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

class DomainBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)

# 创建数据库表
with app.app_context():
    db.create_all()

# 常见公共DNS服务器IP列表（保持不变）
PUBLIC_DNS_SERVERS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6',
    '84.200.69.80', '84.200.70.40', '8.26.56.26', '8.20.247.20',
    '9.9.9.10', '149.112.112.10', '94.140.14.14', '94.140.15.15',
    '223.5.5.5', '223.6.6.6', '119.29.29.29', '182.254.116.116',
    '180.76.76.76', '114.114.114.114', '114.114.115.115', '101.226.4.6',
    '218.30.118.6',
    # 省略其他DNS服务器...
]

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
        
def is_valid_domain(domain):
    # 简单的域名格式验证，先将域名转换为小写再验证
    domain = domain.lower()
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if '..' in domain:
        return False
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    messages = []
    success = None

    if request.method == 'POST':
        input_text = request.form.get('ips', '')
        items = [item.strip() for item in input_text.splitlines() if item.strip()]

        # 验证输入格式
        invalid_items = []
        valid_ips = []
        valid_domains = []
        for item in items:
            # 若为IP则直接判断，否则当作域名处理（转换为小写）
            if is_valid_ip(item):
                valid_ips.append(item)
            elif is_valid_domain(item):
                valid_domains.append(item.lower())
            else:
                invalid_items.append(item)
        if invalid_items:
            messages.append(f"无效IP地址或域名：{', '.join(invalid_items)}")

        # 处理查询请求
        if request.form.get('action') == '查询':
            results = []
            for item in items:
                if is_valid_ip(item):
                    exists = BlockedIP.query.filter_by(ip=item).first() is not None
                elif is_valid_domain(item):
                    exists = DomainBlock.query.filter_by(domain=item.lower()).first() is not None
                else:
                    results.append((item, False))
                    continue
                results.append((item, exists))
            
            for item, exists in results:
                if exists:
                    messages.append(f'{item} 存在于封堵列表中')
                else:
                    messages.append(f'<span class="not-exist">{item} 不存在于封堵列表中</span>')
            
            return render_template('index.html', messages=messages, success=None)

        # 处理封堵请求
        elif request.form.get('action') == '封堵':
            whitelist_ips = []
            existing_ips = []
            to_block_ips = []
            existing_domains = []
            to_block_domains = []

            for item in valid_ips + valid_domains:
                if is_valid_ip(item):
                    if WhitelistIP.query.filter_by(ip=item).first():
                        whitelist_ips.append(item)
                    elif BlockedIP.query.filter_by(ip=item).first():
                        existing_ips.append(item)
                    else:
                        to_block_ips.append(item)
                else:  # 此处均为域名（已转换为小写）
                    if DomainBlock.query.filter_by(domain=item).first():
                        existing_domains.append(item)
                    else:
                        to_block_domains.append(item)

            if whitelist_ips:
                messages.append(f"白名单IP无法封堵：<br>{'<br>'.join(whitelist_ips)}")
            if existing_ips:
                messages.append(f"IP已存在封禁列表：<br>{'<br>'.join(existing_ips)}")
            if existing_domains:
                messages.append(f"域名已存在封禁列表：<br>{'<br>'.join(existing_domains)}")

            if to_block_ips or to_block_domains:
                try:
                    for ip in to_block_ips:
                        blocked_ip = BlockedIP(ip=ip, created_at=datetime.now())
                        db.session.add(blocked_ip)
                    for domain in to_block_domains:
                        blocked_domain = DomainBlock(domain=domain)
                        db.session.add(blocked_domain)
                    db.session.commit()
                    success = f"成功封堵以下IP或域名：<br>{'<br>'.join(to_block_ips + to_block_domains)}"
                except Exception as e:
                    db.session.rollback()
                    messages.append(f"封堵失败：{str(e)}")
        
        # 处理解封请求
        elif request.form.get('action') == '解封':
            whitelist_ips = []
            existing_ips = []
            to_unblock_ips = []
            existing_domains = []
            to_unblock_domains = []

            for ip in valid_ips:
                if WhitelistIP.query.filter_by(ip=ip).first():
                    whitelist_ips.append(ip)
                elif BlockedIP.query.filter_by(ip=ip).first():
                    existing_ips.append(ip)
                    to_unblock_ips.append(ip)

            for domain in valid_domains:
                # 这里注意域名已转为小写
                if DomainBlock.query.filter_by(domain=domain).first():
                    existing_domains.append(domain)
                    to_unblock_domains.append(domain)

            if whitelist_ips:
                messages.append(f"白名单IP无法解封：<br>{'<br>'.join(whitelist_ips)}")
            if existing_ips:
                messages.append(f"以下IP将被解封：<br>{'<br>'.join(existing_ips)}")
            if existing_domains:
                messages.append(f"以下域名将被解封：<br>{'<br>'.join(existing_domains)}")

            if to_unblock_ips or to_unblock_domains:
                try:
                    # 解封IP
                    for ip in to_unblock_ips:
                        blocked_ip = BlockedIP.query.filter_by(ip=ip).first()
                        if blocked_ip:
                            db.session.delete(blocked_ip)
                            if not UnblockedIP.query.filter_by(ip=ip).first():
                                unblocked_ip = UnblockedIP(ip=ip, unblocked_at=datetime.now())
                                db.session.add(unblocked_ip)
                    # 解封域名
                    for domain in to_unblock_domains:
                        blocked_domain = DomainBlock.query.filter_by(domain=domain).first()
                        if blocked_domain:
                            db.session.delete(blocked_domain)
                    db.session.commit()
                    success = "IP和域名解封成功！"
                except Exception as e:
                    db.session.rollback()
                    messages.append(f"解封失败：{str(e)}")
                    app.logger.error(f"解封失败: {str(e)}")

        return render_template('index.html', messages=messages, success=success)

    return render_template('index.html', messages=messages, success=success)

@app.route('/confirm_init_db')
def confirm_init_db():
    print('数据库已初始化')
    return '数据库已初始化'

@app.route('/export_ips')
def export_ips():
    blocked_ips = [ip.ip for ip in BlockedIP.query.all()]
    whitelist_ips = [ip.ip for ip in WhitelistIP.query.all()]
    unblocked_ips = [ip.ip for ip in UnblockedIP.query.all()]
    
    output = "封禁IP列表:\n" + '\n'.join(blocked_ips) + "\n\n白名单IP列表:\n" + '\n'.join(whitelist_ips) + "\n\n已解封IP列表:\n" + '\n'.join(unblocked_ips)
    
    return output, 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=ip_lists.txt'}

if __name__ == '__main__':
    app.run(debug=False, port=5000)
