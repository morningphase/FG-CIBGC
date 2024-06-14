import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.font_manager import FontProperties
from matplotlib.patches import BoxStyle

custom_font = FontProperties(family='Georgia', size=12)

fig, axes = plt.subplots(nrows=2, ncols=2)


plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1, wspace=0.4, hspace=0.6)

for ax in axes.flatten():
    labels = ['FWT', 'BWT']
    a = [0.15, -0.15]
    b = [0.09, -0.09]
    c = [0.11, -0.11]
    d = [0.08, -0.08]
    e = [0.13, -0.13]

    x = np.arange(len(labels)) 
    width = 0.12 

    rects1 = ax.bar(x - width * 2, a, width, label='MEAN')
    rects2 = ax.bar(x - width + 0.01, b, width, label='PNN')
    rects3 = ax.bar(x + 0.02, c, width, label='SI')
    rects4 = ax.bar(x + width + 0.03, d, width, label='GEM')
    rects5 = ax.bar(x + width * 2 + 0.04, e, width, label='DiCGRL')


    ax.set_title('')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontproperties=custom_font, fontsize=12)

    ax.tick_params(axis='x', which='major', pad=8)

    ax.set_yticks(np.arange(-0.25, 0.30, 0.05))


    legend = ax.legend(loc='lower left', ncol=1,prop={'size':6},handlelength=1, handleheight=1,edgecolor='black')

    frame = legend.get_frame()
    frame.set_linewidth(0.4)

    plt.text(0.95, 0.95, 'Entity', fontproperties=custom_font, fontsize=12, color='black', weight='bold', ha='right',
             va='top', transform=ax.transAxes)

    ax.spines['top'].set_linewidth(1)  
    ax.spines['right'].set_linewidth(1)  
    ax.spines['bottom'].set_linewidth(1)  
    ax.spines['left'].set_linewidth(1) 

plt.show()
